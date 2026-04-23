"""
╔══════════════════════════════════════════════════════════════════════════╗
║                       mFast — Anti-nuke serveur                          ║
║                                                                          ║
║  Bot de sécurité qui surveille toutes les actions sensibles sur le       ║
║  serveur via les audit logs. Détecte les abus (dépassement de limites    ║
║  configurées) et réagit : ban direct de l'auteur + tentative de revert.  ║
║                                                                          ║
║  Backup automatique de la structure (rôles, salons, permissions) au      ║
║  démarrage et toutes les 60min.                                          ║
║                                                                          ║
║  Accès aux commandes : Buyer uniquement.                                 ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
import discord
from discord.ext import commands, tasks
import os
import sys
import sqlite3
import json
import asyncio
import logging
import traceback
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

# ========================= CONFIG =========================
BOT_TOKEN = os.environ.get("TOKEN_MFAST") or os.environ.get("TOKEN")
if not BOT_TOKEN:
    print("[ERREUR CRITIQUE] TOKEN_MFAST (ou TOKEN) non défini.")
    sys.exit(1)

PARIS_TZ = ZoneInfo("Europe/Paris")
DEFAULT_BUYER_IDS = [1312375517927706630, 1312375955737542676]
DEFAULT_PREFIX = "%"
DB_PATH = "mfast.db"

# Intervalle entre chaque backup auto (minutes)
BACKUP_INTERVAL_MIN = 60
# Nb max de backups gardés par guild (on purge les vieux)
MAX_BACKUPS_PER_GUILD = 10
# Durée après laquelle on purge l'historique des actions (jours)
ACTION_HISTORY_DAYS = 30

# Logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%d/%m/%Y %H:%M:%S",
)
log = logging.getLogger("mfast")

# Cache prefix
_prefix_cache = {"value": None}

# ========================= ACTIONS SURVEILLÉES =========================
# Liste complète des types d'action que le bot surveille.
# Chaque action a un nom court + description pour l'admin.
WATCHED_ACTIONS = {
    # Membres
    "ban":                "Bannir un membre",
    "unban":              "Débannir un membre",
    "kick":               "Expulser un membre",
    "timeout":            "Timeout (mute Discord) un membre",
    "vdisconnect":        "Déconnecter quelqu'un d'un vocal",
    "vmove":              "Déplacer quelqu'un entre vocaux",
    "member_role_add":    "Ajouter un rôle à un membre",
    "member_role_remove": "Retirer un rôle à un membre",
    "member_nick":        "Modifier le pseudo d'un membre",

    # Rôles
    "role_create":        "Créer un rôle",
    "role_delete":        "Supprimer un rôle",
    "role_update":        "Modifier un rôle (nom, couleur, perms, etc.)",
    "role_grant_admin":   "Donner la permission Admin à un rôle",

    # Salons
    "channel_create":     "Créer un salon",
    "channel_delete":     "Supprimer un salon",
    "channel_update":     "Modifier un salon (nom, topic, etc.)",
    "overwrite_update":   "Modifier les permissions d'un salon (dérogations)",

    # Serveur
    "guild_update":       "Modifier le serveur (nom, icône, etc.)",
    "webhook_create":     "Créer un webhook",
    "webhook_delete":     "Supprimer un webhook",
    "emoji_create":       "Créer un emoji",
    "emoji_delete":       "Supprimer un emoji",
    "bot_add":            "Ajouter un bot au serveur",
}


# ========================= LIMITES PAR DÉFAUT =========================
# Format : {action: {rank: (max_actions, window_minutes)}}
# rank: 1=WL, 2=Owner, 3=Sys, 4=Buyer (illimité, pas listé)
# Valeur (0, *) = interdit complètement
# Si une action n'a pas d'entrée pour un rang, elle est interdite pour ce rang

DEFAULT_LIMITS = {
    # --- Membres ---
    "ban":                {1: (2, 30),  2: (5, 30),   3: (15, 30)},
    "unban":              {1: (5, 60),  2: (15, 60),  3: (30, 60)},
    "kick":               {1: (3, 30),  2: (10, 30),  3: (25, 30)},
    "timeout":            {1: (10, 30), 2: (25, 30),  3: (50, 30)},
    "vdisconnect":        {1: (10, 30), 2: (30, 30),  3: (60, 30)},
    "vmove":              {1: (15, 30), 2: (30, 30),  3: (60, 30)},
    "member_role_add":    {1: (10, 30), 2: (30, 30),  3: (60, 30)},
    "member_role_remove": {1: (10, 30), 2: (30, 30),  3: (60, 30)},
    "member_nick":        {1: (10, 30), 2: (30, 30),  3: (60, 30)},

    # --- Rôles ---
    "role_create":        {1: (1, 60),  2: (3, 60),   3: (10, 60)},
    "role_delete":        {1: (0, 0),   2: (1, 60),   3: (5, 60)},      # WL interdit
    "role_update":        {1: (2, 60),  2: (10, 60),  3: (25, 60)},
    "role_grant_admin":   {1: (0, 0),   2: (0, 0),    3: (1, 1440)},    # Très rare

    # --- Salons ---
    "channel_create":     {1: (2, 60),  2: (5, 60),   3: (15, 60)},
    "channel_delete":     {1: (0, 0),   2: (2, 60),   3: (10, 60)},     # WL interdit
    "channel_update":     {1: (5, 60),  2: (15, 60),  3: (40, 60)},
    "overwrite_update":   {1: (5, 60),  2: (15, 60),  3: (40, 60)},

    # --- Serveur ---
    "guild_update":       {1: (0, 0),   2: (2, 1440), 3: (10, 1440)},
    "webhook_create":     {1: (0, 0),   2: (2, 60),   3: (5, 60)},
    "webhook_delete":     {1: (2, 60),  2: (5, 60),   3: (15, 60)},
    "emoji_create":       {1: (5, 60),  2: (15, 60),  3: (30, 60)},
    "emoji_delete":       {1: (2, 60),  2: (10, 60),  3: (25, 60)},
    "bot_add":            {1: (0, 0),   2: (1, 1440), 3: (3, 1440)},
}


# ========================= DATABASE =========================

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # Config générale
    c.execute("""CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY, value TEXT
    )""")

    # Rangs (WL=1, Owner=2, Sys=3, Buyer=4 via config)
    c.execute("""CREATE TABLE IF NOT EXISTS ranks (
        user_id TEXT PRIMARY KEY, rank INTEGER NOT NULL
    )""")

    # Salon de logs
    c.execute("""CREATE TABLE IF NOT EXISTS log_channels (
        guild_id TEXT PRIMARY KEY, channel_id TEXT NOT NULL
    )""")

    # Historique des actions surveillées (pour fenêtre glissante)
    c.execute("""CREATE TABLE IF NOT EXISTS action_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        action TEXT NOT NULL,
        target_id TEXT,
        target_name TEXT,
        details TEXT,
        created_at TEXT NOT NULL,
        reverted INTEGER DEFAULT 0
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_action_user ON action_history(user_id, action, created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_action_guild ON action_history(guild_id, created_at)")

    # Historique des bans auto appliqués par mFast
    c.execute("""CREATE TABLE IF NOT EXISTS auto_bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        action_trigger TEXT NOT NULL,
        limit_max INTEGER,
        limit_window INTEGER,
        actions_count INTEGER,
        banned_at TEXT NOT NULL,
        reverted INTEGER DEFAULT 0
    )""")

    # Backups de la structure serveur
    c.execute("""CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        trigger TEXT,  -- 'auto', 'manual', 'startup'
        roles_json TEXT,
        channels_json TEXT,
        guild_json TEXT,
        members_roles_json TEXT  -- {user_id: [role_ids]} pour pouvoir réattribuer
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_backups_guild ON backups(guild_id, created_at DESC)")

    # Lockdown state
    c.execute("""CREATE TABLE IF NOT EXISTS lockdown_state (
        guild_id TEXT PRIMARY KEY,
        enabled INTEGER DEFAULT 0,
        enabled_at TEXT,
        enabled_by TEXT,
        saved_perms TEXT  -- JSON {role_id: perm_bitmask} pour restore
    )""")

    # Bots whitelist (bypass total comme Buyer)
    c.execute("""CREATE TABLE IF NOT EXISTS whitelisted_bots (
        guild_id TEXT NOT NULL,
        bot_user_id TEXT NOT NULL,
        bot_name TEXT,
        added_by TEXT,
        added_at TEXT,
        PRIMARY KEY (guild_id, bot_user_id)
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_wl_bots_guild ON whitelisted_bots(guild_id)")

    # Catégorie de logs (un salon par type d'action)
    c.execute("""CREATE TABLE IF NOT EXISTS log_category (
        guild_id TEXT PRIMARY KEY,
        category_id TEXT NOT NULL,
        set_at TEXT,
        set_by TEXT
    )""")

    # Mapping action → salon de log
    c.execute("""CREATE TABLE IF NOT EXISTS log_action_channels (
        guild_id TEXT NOT NULL,
        action TEXT NOT NULL,
        channel_id TEXT NOT NULL,
        PRIMARY KEY (guild_id, action)
    )""")

    # Defaults
    c.execute("INSERT OR IGNORE INTO config VALUES ('prefix', ?)", (DEFAULT_PREFIX,))
    c.execute("INSERT OR IGNORE INTO config VALUES ('buyer_ids', ?)",
              (json.dumps([str(i) for i in DEFAULT_BUYER_IDS]),))
    c.execute("INSERT OR IGNORE INTO config VALUES ('limits', ?)",
              (json.dumps({k: {str(rk): list(rv) for rk, rv in v.items()}
                          for k, v in DEFAULT_LIMITS.items()}),))

    conn.commit()
    conn.close()


# ========================= CONFIG =========================

def get_config(key):
    conn = get_db()
    row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else None


def set_config(key, value):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO config VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()
    if key == "prefix":
        _prefix_cache["value"] = str(value)


def get_prefix_cached():
    if _prefix_cache["value"] is None:
        _prefix_cache["value"] = get_config("prefix") or DEFAULT_PREFIX
    return _prefix_cache["value"]


# ========================= RANGS =========================

def get_rank(user_id):
    """Retourne 0-4. Buyer vient de config, les autres de la table ranks."""
    buyer_ids_raw = get_config("buyer_ids")
    if buyer_ids_raw:
        try:
            buyer_ids = json.loads(buyer_ids_raw)
            if str(user_id) in buyer_ids:
                return 4
        except (json.JSONDecodeError, TypeError):
            pass
    conn = get_db()
    row = conn.execute("SELECT rank FROM ranks WHERE user_id = ?", (str(user_id),)).fetchone()
    conn.close()
    return row["rank"] if row else 0


def set_rank(user_id, rank):
    conn = get_db()
    if rank == 0:
        conn.execute("DELETE FROM ranks WHERE user_id = ?", (str(user_id),))
    else:
        conn.execute("INSERT OR REPLACE INTO ranks VALUES (?, ?)", (str(user_id), int(rank)))
    conn.commit()
    conn.close()


def get_ranks_by_level(level):
    conn = get_db()
    rows = conn.execute("SELECT user_id FROM ranks WHERE rank = ?", (level,)).fetchall()
    conn.close()
    return [r["user_id"] for r in rows]


def has_min_rank(user_id, minimum):
    return get_rank(user_id) >= minimum


def rank_name(level):
    return {4: "Buyer", 3: "Sys", 2: "Owner", 1: "WL", 0: "Aucun"}.get(level, "Aucun")


def is_whitelisted(user_id):
    """True si le user est WL+ (donc autorisé à faire des actions sur le serveur sans être ban)."""
    return get_rank(user_id) >= 1


def is_buyer(user_id):
    return get_rank(user_id) == 4


# ========================= LOG CHANNEL =========================

def get_log_channel(guild_id):
    conn = get_db()
    row = conn.execute("SELECT channel_id FROM log_channels WHERE guild_id = ?",
                       (str(guild_id),)).fetchone()
    conn.close()
    return row["channel_id"] if row else None


def set_log_channel(guild_id, channel_id):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO log_channels VALUES (?, ?)",
                 (str(guild_id), str(channel_id)))
    conn.commit()
    conn.close()


# ========================= LIMITES =========================

def get_limits():
    """Retourne {action: {rank_int: (max, minutes)}}"""
    raw = get_config("limits")
    if not raw:
        return dict(DEFAULT_LIMITS)
    try:
        parsed = json.loads(raw)
        result = {}
        for action, ranks in parsed.items():
            result[action] = {int(k): tuple(v) for k, v in ranks.items()}
        return result
    except (json.JSONDecodeError, TypeError, ValueError):
        return dict(DEFAULT_LIMITS)


def set_limit(action, rank, max_actions, window_minutes):
    limits = get_limits()
    if action not in limits:
        limits[action] = {}
    limits[action][int(rank)] = (int(max_actions), int(window_minutes))
    serializable = {a: {str(rk): list(v) for rk, v in rvs.items()}
                    for a, rvs in limits.items()}
    set_config("limits", json.dumps(serializable))


def remove_limit(action, rank):
    limits = get_limits()
    if action in limits and int(rank) in limits[action]:
        del limits[action][int(rank)]
        serializable = {a: {str(rk): list(v) for rk, v in rvs.items()}
                        for a, rvs in limits.items()}
        set_config("limits", json.dumps(serializable))
        return True
    return False


def get_limit_for(action, rank):
    """Retourne (max, minutes) ou None si pas de limite (illimité).
    Si (0, *) → interdit complet."""
    if int(rank) == 4:  # Buyer illimité
        return None
    limits = get_limits()
    action_limits = limits.get(action, {})
    val = action_limits.get(int(rank))
    if val is None:
        # Pas de limite configurée = interdit par sécurité
        return (0, 0)
    return val


# ========================= ACTION HISTORY =========================

def record_action(guild_id, user_id, action, target_id=None, target_name=None, details=None):
    conn = get_db()
    now = datetime.now(PARIS_TZ).isoformat()
    cur = conn.execute("""INSERT INTO action_history
        (guild_id, user_id, action, target_id, target_name, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (str(guild_id), str(user_id), action,
         str(target_id) if target_id else None, target_name, details, now))
    action_id = cur.lastrowid
    conn.commit()
    conn.close()
    return action_id


def count_recent_actions(user_id, guild_id, action, window_minutes):
    conn = get_db()
    cutoff = (datetime.now(PARIS_TZ) - timedelta(minutes=window_minutes)).isoformat()
    row = conn.execute("""SELECT COUNT(*) as c FROM action_history
        WHERE user_id = ? AND guild_id = ? AND action = ? AND created_at >= ?""",
        (str(user_id), str(guild_id), action, cutoff)).fetchone()
    conn.close()
    return row["c"] if row else 0


def get_user_history(user_id, guild_id, limit=50):
    conn = get_db()
    rows = conn.execute("""SELECT * FROM action_history
        WHERE user_id = ? AND guild_id = ?
        ORDER BY created_at DESC LIMIT ?""",
        (str(user_id), str(guild_id), limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_actions(guild_id, limit=50):
    conn = get_db()
    rows = conn.execute("""SELECT * FROM action_history
        WHERE guild_id = ? ORDER BY created_at DESC LIMIT ?""",
        (str(guild_id), limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_action_reverted(action_id):
    conn = get_db()
    conn.execute("UPDATE action_history SET reverted = 1 WHERE id = ?", (int(action_id),))
    conn.commit()
    conn.close()


def cleanup_old_history():
    conn = get_db()
    cutoff = (datetime.now(PARIS_TZ) - timedelta(days=ACTION_HISTORY_DAYS)).isoformat()
    conn.execute("DELETE FROM action_history WHERE created_at < ?", (cutoff,))
    conn.commit()
    conn.close()


# ========================= AUTO-BANS =========================

def record_auto_ban(guild_id, user_id, action, max_limit, window, count):
    conn = get_db()
    now = datetime.now(PARIS_TZ).isoformat()
    cur = conn.execute("""INSERT INTO auto_bans
        (guild_id, user_id, action_trigger, limit_max, limit_window, actions_count, banned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (str(guild_id), str(user_id), action, int(max_limit), int(window),
         int(count), now))
    ban_id = cur.lastrowid
    conn.commit()
    conn.close()
    return ban_id


def get_recent_auto_bans(guild_id, limit=20):
    conn = get_db()
    rows = conn.execute("""SELECT * FROM auto_bans
        WHERE guild_id = ? ORDER BY banned_at DESC LIMIT ?""",
        (str(guild_id), limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ========================= BACKUPS =========================

def save_backup(guild_id, trigger, roles_data, channels_data, guild_data, members_roles_data):
    conn = get_db()
    now = datetime.now(PARIS_TZ).isoformat()
    cur = conn.execute("""INSERT INTO backups
        (guild_id, created_at, trigger, roles_json, channels_json, guild_json, members_roles_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (str(guild_id), now, trigger,
         json.dumps(roles_data),
         json.dumps(channels_data),
         json.dumps(guild_data),
         json.dumps(members_roles_data)))
    backup_id = cur.lastrowid

    # Nettoyage : ne garde que les N plus récents
    conn.execute("""DELETE FROM backups WHERE id IN (
        SELECT id FROM backups WHERE guild_id = ?
        ORDER BY created_at DESC LIMIT -1 OFFSET ?
    )""", (str(guild_id), MAX_BACKUPS_PER_GUILD))

    conn.commit()
    conn.close()
    return backup_id


def list_backups(guild_id):
    conn = get_db()
    rows = conn.execute("""SELECT id, created_at, trigger FROM backups
        WHERE guild_id = ? ORDER BY created_at DESC""",
        (str(guild_id),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_backup(backup_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM backups WHERE id = ?", (int(backup_id),)).fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    # Parse les JSON
    for key in ("roles_json", "channels_json", "guild_json", "members_roles_json"):
        if data.get(key):
            try:
                data[key.replace("_json", "")] = json.loads(data[key])
            except (json.JSONDecodeError, TypeError):
                data[key.replace("_json", "")] = None
        else:
            data[key.replace("_json", "")] = None
    return data


def get_latest_backup(guild_id):
    conn = get_db()
    row = conn.execute("""SELECT id FROM backups WHERE guild_id = ?
        ORDER BY created_at DESC LIMIT 1""",
        (str(guild_id),)).fetchone()
    conn.close()
    return get_backup(row["id"]) if row else None


# ========================= LOCKDOWN =========================

def get_lockdown_state(guild_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM lockdown_state WHERE guild_id = ?",
                       (str(guild_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def set_lockdown(guild_id, enabled, enabled_by=None, saved_perms=None):
    conn = get_db()
    now = datetime.now(PARIS_TZ).isoformat() if enabled else None
    if enabled:
        conn.execute("""INSERT OR REPLACE INTO lockdown_state
            (guild_id, enabled, enabled_at, enabled_by, saved_perms) VALUES (?, 1, ?, ?, ?)""",
            (str(guild_id), now, str(enabled_by) if enabled_by else None,
             json.dumps(saved_perms) if saved_perms else None))
    else:
        conn.execute("DELETE FROM lockdown_state WHERE guild_id = ?", (str(guild_id),))
    conn.commit()
    conn.close()


# ========================= BOTS WHITELIST =========================

def wl_bot_add(guild_id, bot_user_id, bot_name, added_by):
    conn = get_db()
    now = datetime.now(PARIS_TZ).isoformat()
    conn.execute("""INSERT OR REPLACE INTO whitelisted_bots
        (guild_id, bot_user_id, bot_name, added_by, added_at) VALUES (?, ?, ?, ?, ?)""",
        (str(guild_id), str(bot_user_id), bot_name, str(added_by), now))
    conn.commit()
    conn.close()


def wl_bot_remove(guild_id, bot_user_id):
    conn = get_db()
    cur = conn.execute("""DELETE FROM whitelisted_bots
        WHERE guild_id = ? AND bot_user_id = ?""",
        (str(guild_id), str(bot_user_id)))
    affected = cur.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def wl_bot_is_whitelisted(guild_id, bot_user_id):
    """True si ce bot est whitelist sur cette guild (bypass total)."""
    conn = get_db()
    row = conn.execute("""SELECT 1 FROM whitelisted_bots
        WHERE guild_id = ? AND bot_user_id = ? LIMIT 1""",
        (str(guild_id), str(bot_user_id))).fetchone()
    conn.close()
    return row is not None


def wl_bot_list(guild_id):
    conn = get_db()
    rows = conn.execute("""SELECT * FROM whitelisted_bots
        WHERE guild_id = ? ORDER BY added_at ASC""",
        (str(guild_id),)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ========================= LOG CATEGORY (salons par action) =========================

def set_log_category(guild_id, category_id, set_by):
    conn = get_db()
    now = datetime.now(PARIS_TZ).isoformat()
    conn.execute("""INSERT OR REPLACE INTO log_category
        (guild_id, category_id, set_at, set_by) VALUES (?, ?, ?, ?)""",
        (str(guild_id), str(category_id), now, str(set_by)))
    conn.commit()
    conn.close()


def get_log_category(guild_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM log_category WHERE guild_id = ?",
                       (str(guild_id),)).fetchone()
    conn.close()
    return dict(row) if row else None


def set_action_channel(guild_id, action, channel_id):
    conn = get_db()
    conn.execute("""INSERT OR REPLACE INTO log_action_channels
        (guild_id, action, channel_id) VALUES (?, ?, ?)""",
        (str(guild_id), action, str(channel_id)))
    conn.commit()
    conn.close()


def get_action_channel(guild_id, action):
    """Retourne l'ID du salon log dédié à cette action (ou None)."""
    conn = get_db()
    row = conn.execute("""SELECT channel_id FROM log_action_channels
        WHERE guild_id = ? AND action = ?""",
        (str(guild_id), action)).fetchone()
    conn.close()
    return row["channel_id"] if row else None


def get_all_action_channels(guild_id):
    conn = get_db()
    rows = conn.execute("SELECT action, channel_id FROM log_action_channels WHERE guild_id = ?",
                       (str(guild_id),)).fetchall()
    conn.close()
    return {r["action"]: r["channel_id"] for r in rows}


def clear_action_channels(guild_id):
    """Vide le mapping action→salon (utile si on refait %categorie)."""
    conn = get_db()
    conn.execute("DELETE FROM log_action_channels WHERE guild_id = ?", (str(guild_id),))
    conn.commit()
    conn.close()


# ========================= BUILD SNAPSHOT =========================

def build_guild_snapshot(guild):
    """Construit un snapshot complet de la structure du serveur."""
    roles_data = []
    for role in sorted(guild.roles, key=lambda r: r.position, reverse=True):
        if role.is_default():
            # On save aussi @everyone pour ses perms, mais on ne le recréera pas
            roles_data.append({
                "id": str(role.id),
                "name": role.name,
                "is_default": True,
                "permissions": role.permissions.value,
                "color": role.color.value,
                "position": role.position,
                "mentionable": role.mentionable,
                "hoist": role.hoist,
            })
            continue
        if role.managed:
            # Rôle géré par intégration (bot, boost, etc.) — on save mais pas recréable
            roles_data.append({
                "id": str(role.id),
                "name": role.name,
                "is_managed": True,
                "permissions": role.permissions.value,
                "color": role.color.value,
                "position": role.position,
                "mentionable": role.mentionable,
                "hoist": role.hoist,
            })
            continue
        roles_data.append({
            "id": str(role.id),
            "name": role.name,
            "is_default": False,
            "is_managed": False,
            "permissions": role.permissions.value,
            "color": role.color.value,
            "position": role.position,
            "mentionable": role.mentionable,
            "hoist": role.hoist,
        })

    channels_data = []
    for ch in sorted(guild.channels, key=lambda c: (c.category.position if c.category else -1, c.position)):
        overrides = {}
        for target, overwrite in ch.overwrites.items():
            allow, deny = overwrite.pair()
            overrides[str(target.id)] = {
                "type": "role" if isinstance(target, discord.Role) else "member",
                "name": target.name if hasattr(target, "name") else str(target),
                "allow": allow.value,
                "deny": deny.value,
            }
        channels_data.append({
            "id": str(ch.id),
            "name": ch.name,
            "type": str(ch.type),
            "position": ch.position,
            "category_id": str(ch.category.id) if ch.category else None,
            "category_name": ch.category.name if ch.category else None,
            "topic": getattr(ch, "topic", None),
            "nsfw": getattr(ch, "nsfw", False),
            "slowmode_delay": getattr(ch, "slowmode_delay", 0),
            "bitrate": getattr(ch, "bitrate", None),
            "user_limit": getattr(ch, "user_limit", None),
            "overwrites": overrides,
        })

    guild_data = {
        "id": str(guild.id),
        "name": guild.name,
        "verification_level": str(guild.verification_level),
        "mfa_level": int(guild.mfa_level) if hasattr(guild, "mfa_level") else 0,
        "default_notifications": str(guild.default_notifications),
        "explicit_content_filter": str(guild.explicit_content_filter),
        "afk_timeout": guild.afk_timeout,
        "afk_channel_id": str(guild.afk_channel.id) if guild.afk_channel else None,
        "system_channel_id": str(guild.system_channel.id) if guild.system_channel else None,
    }

    # Tracking membres → rôles
    members_roles_data = {}
    for member in guild.members:
        if member.bot:
            continue
        role_ids = [str(r.id) for r in member.roles if not r.is_default() and not r.managed]
        if role_ids:
            members_roles_data[str(member.id)] = role_ids

    return roles_data, channels_data, guild_data, members_roles_data


async def do_backup(guild, trigger="auto"):
    """Effectue un backup du serveur. Retourne (backup_id, error_msg)."""
    try:
        roles_data, channels_data, guild_data, members_roles_data = build_guild_snapshot(guild)
        backup_id = save_backup(guild.id, trigger, roles_data, channels_data, guild_data, members_roles_data)
        log.info(f"Backup {trigger} #{backup_id} pour {guild.name} : "
                 f"{len(roles_data)} rôles, {len(channels_data)} salons, "
                 f"{len(members_roles_data)} membres trackés")
        return backup_id, None
    except Exception as e:
        err_msg = f"{type(e).__name__}: {e}"
        log.error(f"Erreur backup {guild.name} ({trigger}) : {err_msg}\n{traceback.format_exc()}")
        return None, err_msg


# ========================= HELPERS EMBED =========================

def embed_color():
    return 0x2b2d31


def success_embed(title, desc=""):
    em = discord.Embed(title=title, description=desc, color=0x43b581)
    em.set_footer(text="mFast")
    return em


def error_embed(title, desc=""):
    em = discord.Embed(title=title, description=desc, color=0xf04747)
    em.set_footer(text="mFast")
    return em


def info_embed(title, desc=""):
    em = discord.Embed(title=title, description=desc, color=embed_color())
    em.set_footer(text="mFast")
    return em


def warning_embed(title, desc=""):
    em = discord.Embed(title=title, description=desc, color=0xf1c40f)
    em.set_footer(text="mFast")
    return em


def critical_embed(title, desc=""):
    em = discord.Embed(title=title, description=desc, color=0xf04747)
    em.set_footer(text="mFast ・ ALERTE CRITIQUE")
    return em


def format_french_date():
    now = datetime.now(PARIS_TZ)
    JOURS = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"]
    MOIS = ["janvier", "février", "mars", "avril", "mai", "juin",
            "juillet", "août", "septembre", "octobre", "novembre", "décembre"]
    return f"{JOURS[now.weekday()]} {now.day} {MOIS[now.month-1]} {now.year} — {now.strftime('%Hh%M')}"


def format_datetime(iso_str):
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%d/%m/%Y %Hh%M")
    except (ValueError, TypeError):
        return iso_str or "?"


# ========================= RESOLVE USER =========================

async def resolve_user_or_id(ctx, user_input):
    if not user_input:
        return None, None
    raw = user_input.strip()
    cleaned = raw.strip("<@!>")
    try:
        user_id = int(cleaned)
    except ValueError:
        try:
            m = await commands.MemberConverter().convert(ctx, raw)
            return m, m.id
        except commands.CommandError:
            return None, None
    if ctx.guild:
        member = ctx.guild.get_member(user_id)
        if member:
            return member, user_id
    try:
        user = await bot.fetch_user(user_id)
        return user, user_id
    except (discord.NotFound, discord.HTTPException):
        return None, user_id


def format_user_display(display_obj, user_id):
    if display_obj is not None:
        return f"{display_obj.mention} (`{display_obj.id}`)"
    return f"<@{user_id}> (`{user_id}`) *(hors serveur)*"


# ========================= SEND LOG =========================

async def send_log_embed(guild, embed, action=None, content=None):
    """
    Envoie un embed dans le salon de log.
    Si une action est fournie ET qu'un salon dédié existe → envoie dans ce salon.
    Sinon → fallback sur le salon de log global.
    content = message texte (utile pour les mentions)
    """
    channel = None
    # 1. Essayer de router vers le salon spécifique à l'action
    if action:
        action_ch_id = get_action_channel(guild.id, action)
        if action_ch_id:
            channel = guild.get_channel(int(action_ch_id))
    # 2. Fallback : salon log global
    if not channel:
        global_ch_id = get_log_channel(guild.id)
        if global_ch_id:
            channel = guild.get_channel(int(global_ch_id))
    if not channel:
        return
    try:
        await channel.send(content=content, embed=embed,
                          allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False))
    except discord.HTTPException as e:
        log.warning(f"send_log: envoi échoué : {e}")


async def send_log(guild, title, author=None, desc=None, color=0xe74c3c, action=None, content=None):
    em = discord.Embed(title=f"📋 {title}", description=desc or "", color=color)
    if author:
        em.add_field(name="Par", value=f"{author.mention} (`{author.id}`)", inline=False)
    em.set_footer(text=format_french_date())
    await send_log_embed(guild, em, action=action, content=content)


# ========================= BOT SETUP =========================

init_db()
intents = discord.Intents.all()


def get_prefix(bot, message):
    return get_prefix_cached()


bot = commands.Bot(command_prefix=get_prefix, intents=intents, help_command=None)


# ========================= GLOBAL CHECK : BUYER ONLY =========================
# Ce bot est BUYER-ONLY pour les commandes.
# Les events (on_*) tournent toujours, ce sont eux qui protègent le serveur.

class NotBuyerError(commands.CheckFailure):
    pass


@bot.check
async def global_buyer_only(ctx):
    if is_buyer(ctx.author.id):
        return True
    raise NotBuyerError()


# ========================= ERROR HANDLING =========================

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandInvokeError):
        error = error.original
    if isinstance(error, NotBuyerError):
        # Refus TOTALEMENT silencieux, on laisse rien fuir
        try:
            await ctx.message.add_reaction("🔒")
        except discord.HTTPException:
            pass
        return
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=error_embed(
            "❌ Argument manquant",
            f"Il manque : `{error.param.name}`"
        ))
        return
    if isinstance(error, commands.BadArgument):
        await ctx.send(embed=error_embed("❌ Argument invalide", str(error)))
        return
    log.error(f"Erreur non gérée '{ctx.command}' : {error}\n"
              + "".join(traceback.format_exception(type(error), error, error.__traceback__)))
    try:
        await ctx.send(embed=error_embed("❌ Erreur interne", "Voir les logs."))
    except discord.HTTPException:
        pass


# ════════════════════════════════════════════════════════════════════════════
#  PARTIE 2 — WATCHERS, CHECK D'ACTION, BAN AUTO + REVERT
# ════════════════════════════════════════════════════════════════════════════


# ========================= CHECK ACTION LIMIT =========================

async def check_action_and_react(guild, user_id, action, target=None, target_name=None,
                                  revert_fn=None, revert_args=None):
    """
    Fonction centrale. Appelée dès qu'une action surveillée est détectée.

    Logs systématiquement dans le salon dédié à l'action (si configuré), avec
    ping de l'auteur et quota restant.

    1. Bot whitelist → bypass + log info
    2. Buyer → illimité + log info
    3. Non-whitelist (rang 0) → BAN AUTO + revert
    4. WL/Owner/Sys au-dessus de leur limite → BAN AUTO + revert
    5. WL/Owner/Sys dans les clous → record + log avec quota restant
    """
    # Ignore soi-même (c'est le bot qui agit)
    if user_id == bot.user.id:
        return

    target_id = getattr(target, "id", None)
    action_label = WATCHED_ACTIONS.get(action, action)

    # --- Bot whitelist ---
    if wl_bot_is_whitelisted(guild.id, user_id):
        record_action(guild.id, user_id, action,
                     target_id=target_id, target_name=target_name,
                     details="BOT_WHITELIST")
        await _log_action_event(guild, user_id, action, target_name,
                                status="bot", color=0x95a5a6)
        return

    rank = get_rank(user_id)

    # --- Buyer ---
    if rank == 4:
        record_action(guild.id, user_id, action,
                     target_id=target_id, target_name=target_name)
        await _log_action_event(guild, user_id, action, target_name,
                                status="buyer", color=0x9b59b6)
        return

    # --- Non-whitelist : ban direct ---
    if rank == 0:
        action_id = record_action(guild.id, user_id, action,
                                 target_id=target_id, target_name=target_name,
                                 details="NON-WHITELIST")
        await execute_auto_ban(
            guild, user_id, action,
            reason=f"Action `{action}` non autorisée (non whitelist)",
            max_limit=0, window=0, count=1, action_id=action_id,
        )
        if revert_fn:
            await try_revert(guild, revert_fn, revert_args, action_id)
        return

    # --- WL/Owner/Sys : check de la limite ---
    limit = get_limit_for(action, rank)

    # Interdit complet pour ce rang
    if limit == (0, 0):
        action_id = record_action(guild.id, user_id, action,
                                 target_id=target_id, target_name=target_name,
                                 details=f"INTERDIT pour {rank_name(rank)}")
        await execute_auto_ban(
            guild, user_id, action,
            reason=f"Action `{action}` interdite pour un **{rank_name(rank)}**",
            max_limit=0, window=0, count=1, action_id=action_id,
        )
        if revert_fn:
            await try_revert(guild, revert_fn, revert_args, action_id)
        return

    if limit is None:
        # Illimité (ne devrait pas arriver à ce niveau)
        record_action(guild.id, user_id, action,
                     target_id=target_id, target_name=target_name)
        await _log_action_event(guild, user_id, action, target_name,
                                status="ok", rank=rank, color=0x43b581)
        return

    max_actions, window_minutes = limit
    count_before = count_recent_actions(user_id, guild.id, action, window_minutes)

    # Dépassement
    if count_before >= max_actions:
        action_id = record_action(guild.id, user_id, action,
                                 target_id=target_id, target_name=target_name,
                                 details=f"DÉPASSEMENT ({count_before + 1}e en {window_minutes}min)")
        await execute_auto_ban(
            guild, user_id, action,
            reason=(f"Limite dépassée pour `{action}` : "
                    f"{count_before + 1} actions en moins de {window_minutes}min "
                    f"(max autorisé {max_actions}) pour un **{rank_name(rank)}**"),
            max_limit=max_actions, window=window_minutes, count=count_before + 1,
            action_id=action_id,
        )
        if revert_fn:
            await try_revert(guild, revert_fn, revert_args, action_id)
        return

    # Dans les clous → record + log avec quota restant
    record_action(guild.id, user_id, action,
                 target_id=target_id, target_name=target_name)
    new_count = count_before + 1
    remaining = max_actions - new_count
    await _log_action_event(
        guild, user_id, action, target_name,
        status="ok", rank=rank,
        used=new_count, max_actions=max_actions,
        window_minutes=window_minutes, remaining=remaining,
        color=0x43b581 if remaining > max_actions * 0.3 else (0xf1c40f if remaining > 0 else 0xe67e22),
    )


async def _log_action_event(guild, user_id, action, target_name,
                            status="ok", rank=None,
                            used=None, max_actions=None, window_minutes=None, remaining=None,
                            color=0x43b581):
    """Construit et envoie l'embed de log pour une action enregistrée."""
    action_label = WATCHED_ACTIONS.get(action, action)
    now_str = format_french_date()

    # Emoji selon statut
    status_emoji = {
        "ok": "✅",
        "buyer": "👑",
        "bot": "🤖",
    }.get(status, "📋")

    em = discord.Embed(
        title=f"{status_emoji} {action_label}",
        color=color,
    )
    em.add_field(name="Action", value=f"`{action}`", inline=True)
    em.add_field(name="Auteur", value=f"<@{user_id}>", inline=True)
    if rank is not None:
        em.add_field(name="Rang", value=rank_name(rank), inline=True)
    if target_name:
        em.add_field(name="Cible", value=target_name[:100], inline=False)

    # Quota restant pour WL/Owner/Sys
    if used is not None and max_actions is not None:
        bar = "🟢" if remaining > max_actions * 0.5 else ("🟡" if remaining > 0 else "🔴")
        em.add_field(
            name="📊 Quota",
            value=(
                f"{bar} **{used}/{max_actions}** utilisés dans la fenêtre de **{window_minutes}min**\n"
                f"Il te reste **{remaining}** action(s) avant la limite."
            ),
            inline=False,
        )

    em.set_footer(text=f"mFast ・ {now_str}")
    # Ping en content pour que la personne reçoive la notif
    await send_log_embed(guild, em, action=action, content=f"<@{user_id}>")


async def execute_auto_ban(guild, user_id, action, reason, max_limit, window, count, action_id=None):
    """Ban la personne + alerte dans le salon de log."""
    member = guild.get_member(user_id)

    # Log en DB
    ban_id = record_auto_ban(guild.id, user_id, action, max_limit, window, count)

    # DM d'info avant ban (best effort)
    if member:
        try:
            em = discord.Embed(
                title="⛔ Tu as été banni automatiquement par mFast",
                description=(
                    f"Serveur : **{guild.name}**\n\n"
                    f"**Action détectée :** `{action}`\n"
                    f"**Motif :** {reason}\n\n"
                    f"Cette décision est irrévocable sans intervention manuelle du Buyer."
                ),
                color=0xf04747,
            )
            em.set_footer(text="mFast")
            await member.send(embed=em)
        except (discord.Forbidden, discord.HTTPException):
            pass

    # Ban
    try:
        await guild.ban(discord.Object(id=user_id),
                       reason=f"mFast AUTO : {reason}",
                       delete_message_seconds=0)
        log.warning(f"AUTO-BAN {user_id} sur {guild.name} : {reason}")
    except discord.Forbidden:
        log.error(f"AUTO-BAN échoué (permission manquante) sur {user_id}")
    except discord.HTTPException as e:
        log.error(f"AUTO-BAN échoué : {e}")

    # Alerte
    em = critical_embed(
        "🚨 BAN AUTOMATIQUE",
        f"**Auteur :** <@{user_id}> (`{user_id}`)\n"
        f"**Action :** `{action}`\n"
        f"**Rang :** {rank_name(get_rank(user_id))}\n"
        f"**Motif :** {reason}\n"
        f"**Ban ID :** `#{ban_id}`"
        + (f"\n**Action ID :** `#{action_id}`" if action_id else "")
    )
    em.set_footer(text=f"mFast ・ {format_french_date()}")
    await send_log_embed(guild, em)


async def try_revert(guild, revert_fn, revert_args, action_id):
    """Tente d'annuler une action. Logue le résultat."""
    try:
        ok = await revert_fn(guild, *revert_args) if revert_args else await revert_fn(guild)
        if ok:
            mark_action_reverted(action_id) if action_id else None
            em = success_embed(
                "✅ Revert appliqué",
                f"Action `#{action_id}` a été annulée avec succès."
            )
            await send_log_embed(guild, em)
        else:
            em = warning_embed(
                "⚠️ Revert échoué",
                f"L'action `#{action_id}` n'a pas pu être annulée automatiquement."
            )
            await send_log_embed(guild, em)
    except Exception as e:
        log.error(f"Revert erreur : {e}\n{traceback.format_exc()}")


# ========================= AUDIT LOG RESOLVER =========================

async def resolve_audit_actor(guild, action_type, target_id=None, delay=1.5):
    """
    Récupère l'auteur d'une action via l'audit log.
    Attend un court délai pour laisser Discord écrire l'entrée.
    Retourne (user_id, audit_entry) ou (None, None).
    """
    await asyncio.sleep(delay)
    try:
        async for entry in guild.audit_logs(limit=10, action=action_type):
            # Entrée récente (dans les 10 dernières secondes)
            age = (datetime.now(PARIS_TZ) - entry.created_at.astimezone(PARIS_TZ)).total_seconds()
            if age > 10:
                continue
            # Si on a une cible précise, on matche
            if target_id is not None and entry.target is not None:
                if hasattr(entry.target, "id") and entry.target.id == target_id:
                    return entry.user.id if entry.user else None, entry
            else:
                return entry.user.id if entry.user else None, entry
    except discord.Forbidden:
        log.warning(f"Audit logs inaccessibles sur {guild.name}")
    except discord.HTTPException as e:
        log.warning(f"Audit logs erreur : {e}")
    return None, None


# ========================= REVERT FUNCTIONS =========================

async def revert_channel_delete(guild, channel_snapshot):
    """Recrée un salon supprimé à partir de son snapshot."""
    try:
        ch_type = channel_snapshot.get("type", "")
        name = channel_snapshot.get("name", "restored-channel")
        category_id = channel_snapshot.get("category_id")
        category = guild.get_channel(int(category_id)) if category_id else None

        # Reconstruction des overwrites
        overwrites = {}
        for target_id, ow in channel_snapshot.get("overwrites", {}).items():
            target = None
            if ow["type"] == "role":
                target = guild.get_role(int(target_id))
            else:
                target = guild.get_member(int(target_id))
            if target:
                allow = discord.Permissions(int(ow["allow"]))
                deny = discord.Permissions(int(ow["deny"]))
                overwrites[target] = discord.PermissionOverwrite.from_pair(allow, deny)

        if "text" in ch_type or "news" in ch_type:
            new_ch = await guild.create_text_channel(
                name=name, category=category, overwrites=overwrites,
                topic=channel_snapshot.get("topic"),
                nsfw=channel_snapshot.get("nsfw", False),
                slowmode_delay=channel_snapshot.get("slowmode_delay", 0),
                reason="mFast : revert suppression de salon",
            )
        elif "voice" in ch_type:
            new_ch = await guild.create_voice_channel(
                name=name, category=category, overwrites=overwrites,
                bitrate=channel_snapshot.get("bitrate") or 64000,
                user_limit=channel_snapshot.get("user_limit") or 0,
                reason="mFast : revert suppression de salon vocal",
            )
        elif "category" in ch_type:
            new_ch = await guild.create_category(
                name=name, overwrites=overwrites,
                reason="mFast : revert suppression de catégorie",
            )
        else:
            log.warning(f"Revert channel : type {ch_type} non supporté")
            return False
        log.info(f"Revert channel : {name} recréé (ID {new_ch.id})")
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Revert channel échoué : {e}")
        return False


async def revert_role_delete(guild, role_snapshot):
    """Recrée un rôle supprimé à partir du snapshot."""
    try:
        if role_snapshot.get("is_default") or role_snapshot.get("is_managed"):
            return False
        new_role = await guild.create_role(
            name=role_snapshot.get("name", "restored-role"),
            permissions=discord.Permissions(int(role_snapshot.get("permissions", 0))),
            color=discord.Color(int(role_snapshot.get("color", 0))),
            hoist=role_snapshot.get("hoist", False),
            mentionable=role_snapshot.get("mentionable", False),
            reason="mFast : revert suppression de rôle",
        )
        log.info(f"Revert role : {role_snapshot.get('name')} recréé (ID {new_role.id})")
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Revert role échoué : {e}")
        return False


async def revert_role_create(guild, role_id):
    """Supprime un rôle qui a été créé abusivement."""
    try:
        role = guild.get_role(int(role_id))
        if not role:
            return True  # déjà parti
        await role.delete(reason="mFast : revert création abusive de rôle")
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Revert role create échoué : {e}")
        return False


async def revert_channel_create(guild, channel_id):
    """Supprime un salon qui a été créé abusivement."""
    try:
        ch = guild.get_channel(int(channel_id))
        if not ch:
            return True
        await ch.delete(reason="mFast : revert création abusive de salon")
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Revert channel create échoué : {e}")
        return False


async def revert_ban(guild, user_id):
    """Débannit qqn qui a été banni abusivement."""
    try:
        await guild.unban(discord.Object(id=user_id), reason="mFast : revert ban abusif")
        return True
    except (discord.NotFound, discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Revert ban échoué : {e}")
        return False


async def revert_kick(guild, user_id):
    """On peut pas unkick directement, mais on peut préparer une invite et notifier."""
    # Discord ne permet pas de forcer un retour, on log juste
    em = warning_embed(
        "⚠️ Revert kick impossible",
        f"<@{user_id}> a été kick. Il peut revenir avec une invitation.\n"
        f"Action enregistrée pour traçabilité."
    )
    await send_log_embed(guild, em)
    return False


async def revert_member_role_add(guild, user_id, role_id):
    """Retire un rôle qui a été attribué abusivement."""
    try:
        member = guild.get_member(int(user_id))
        role = guild.get_role(int(role_id))
        if not member or not role:
            return False
        if role in member.roles:
            await member.remove_roles(role, reason="mFast : revert attribution abusive de rôle")
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Revert member_role_add échoué : {e}")
        return False


async def revert_member_role_remove(guild, user_id, role_id):
    """Réattribue un rôle qui a été retiré abusivement."""
    try:
        member = guild.get_member(int(user_id))
        role = guild.get_role(int(role_id))
        if not member or not role:
            return False
        if role not in member.roles:
            await member.add_roles(role, reason="mFast : revert retrait abusif de rôle")
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Revert member_role_remove échoué : {e}")
        return False


async def revert_role_update_admin(guild, role_id, old_perms):
    """Annule l'ajout de la perm admin à un rôle."""
    try:
        role = guild.get_role(int(role_id))
        if not role:
            return False
        await role.edit(
            permissions=discord.Permissions(int(old_perms)),
            reason="mFast : revert ajout permission Admin abusif",
        )
        return True
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Revert role_update_admin échoué : {e}")
        return False


# ========================= EVENTS DISCORD : WATCHERS =========================

@bot.event
async def on_ready():
    log.info(f"mFast connecté : {bot.user} ({bot.user.id})")
    await bot.change_presence(
        activity=discord.Activity(type=discord.ActivityType.watching, name="le serveur"),
    )
    # Backup au démarrage de chaque guild
    for guild in bot.guilds:
        await do_backup(guild, trigger="startup")
    # Lancement des boucles
    if not backup_loop.is_running():
        backup_loop.start()
    if not cleanup_loop.is_running():
        cleanup_loop.start()


# -------------------- MEMBRES --------------------

@bot.event
async def on_member_ban(guild, user):
    """Quelqu'un vient d'être banni."""
    actor_id, entry = await resolve_audit_actor(guild, discord.AuditLogAction.ban, target_id=user.id)
    if actor_id is None:
        return
    await check_action_and_react(
        guild, actor_id, "ban",
        target=user, target_name=str(user),
        revert_fn=revert_ban, revert_args=(user.id,),
    )


@bot.event
async def on_member_unban(guild, user):
    actor_id, entry = await resolve_audit_actor(guild, discord.AuditLogAction.unban, target_id=user.id)
    if actor_id is None:
        return
    await check_action_and_react(
        guild, actor_id, "unban",
        target=user, target_name=str(user),
    )


@bot.event
async def on_member_remove(member):
    """Kick détection via audit log."""
    actor_id, entry = await resolve_audit_actor(member.guild, discord.AuditLogAction.kick, target_id=member.id)
    if actor_id is None:
        # Probablement départ volontaire, rien à surveiller
        return
    await check_action_and_react(
        member.guild, actor_id, "kick",
        target=member, target_name=str(member),
        revert_fn=revert_kick, revert_args=(member.id,),
    )


@bot.event
async def on_member_update(before, after):
    """Détecte attribution/retrait de rôle + timeout + changement pseudo."""
    # Timeout (mute Discord)
    if before.timed_out_until != after.timed_out_until and after.timed_out_until is not None:
        actor_id, entry = await resolve_audit_actor(
            after.guild, discord.AuditLogAction.member_update, target_id=after.id)
        if actor_id:
            await check_action_and_react(
                after.guild, actor_id, "timeout",
                target=after, target_name=str(after),
            )

    # Changement de pseudo
    if before.nick != after.nick:
        actor_id, entry = await resolve_audit_actor(
            after.guild, discord.AuditLogAction.member_update, target_id=after.id)
        if actor_id and actor_id != after.id:  # L'utilisateur peut changer son propre pseudo
            await check_action_and_react(
                after.guild, actor_id, "member_nick",
                target=after, target_name=str(after),
            )

    # Changements de rôles
    before_roles = set(before.roles)
    after_roles = set(after.roles)
    added = after_roles - before_roles
    removed = before_roles - after_roles

    for role in added:
        if role.is_default():
            continue
        actor_id, entry = await resolve_audit_actor(
            after.guild, discord.AuditLogAction.member_role_update, target_id=after.id)
        if actor_id is None or actor_id == bot.user.id:
            continue
        await check_action_and_react(
            after.guild, actor_id, "member_role_add",
            target=after, target_name=f"{after} (+rôle {role.name})",
            revert_fn=revert_member_role_add, revert_args=(after.id, role.id),
        )
        # Si le rôle a la perm admin → c'est très critique, on double-alerte
        if role.permissions.administrator:
            em = critical_embed(
                "🚨 RÔLE ADMIN DONNÉ À UN MEMBRE",
                f"**Auteur :** <@{actor_id}>\n"
                f"**Cible :** {after.mention}\n"
                f"**Rôle :** {role.mention} (permissions administrateur)",
            )
            await send_log_embed(after.guild, em)

    for role in removed:
        if role.is_default():
            continue
        actor_id, entry = await resolve_audit_actor(
            after.guild, discord.AuditLogAction.member_role_update, target_id=after.id)
        if actor_id is None or actor_id == bot.user.id:
            continue
        await check_action_and_react(
            after.guild, actor_id, "member_role_remove",
            target=after, target_name=f"{after} (-rôle {role.name})",
            revert_fn=revert_member_role_remove, revert_args=(after.id, role.id),
        )


@bot.event
async def on_voice_state_update(member, before, after):
    """Détecte vdisconnect + vmove forcés par un tiers."""
    # Déconnexion forcée : before.channel existait, after.channel est None,
    # mais c'est pas l'user qui s'est barré
    if before.channel is not None and after.channel is None:
        actor_id, entry = await resolve_audit_actor(
            member.guild, discord.AuditLogAction.member_disconnect, target_id=member.id, delay=1.0)
        if actor_id and actor_id != member.id:
            await check_action_and_react(
                member.guild, actor_id, "vdisconnect",
                target=member, target_name=str(member),
            )
    # Déplacement forcé
    elif before.channel is not None and after.channel is not None and before.channel != after.channel:
        actor_id, entry = await resolve_audit_actor(
            member.guild, discord.AuditLogAction.member_move, target_id=member.id, delay=1.0)
        if actor_id and actor_id != member.id:
            await check_action_and_react(
                member.guild, actor_id, "vmove",
                target=member, target_name=str(member),
            )


# -------------------- RÔLES --------------------

@bot.event
async def on_guild_role_create(role):
    if role.managed:
        return  # géré par intégration
    actor_id, entry = await resolve_audit_actor(
        role.guild, discord.AuditLogAction.role_create, target_id=role.id)
    if actor_id is None:
        return
    await check_action_and_react(
        role.guild, actor_id, "role_create",
        target=role, target_name=role.name,
        revert_fn=revert_role_create, revert_args=(role.id,),
    )


@bot.event
async def on_guild_role_delete(role):
    actor_id, entry = await resolve_audit_actor(
        role.guild, discord.AuditLogAction.role_delete, target_id=role.id)
    if actor_id is None:
        return
    # Pour le revert on utilise le dernier backup
    backup = get_latest_backup(role.guild.id)
    role_snapshot = None
    if backup and backup.get("roles"):
        for r in backup["roles"]:
            if r["id"] == str(role.id):
                role_snapshot = r
                break

    await check_action_and_react(
        role.guild, actor_id, "role_delete",
        target=role, target_name=role.name,
        revert_fn=revert_role_delete if role_snapshot else None,
        revert_args=(role_snapshot,) if role_snapshot else None,
    )


@bot.event
async def on_guild_role_update(before, after):
    # Détecte l'ajout de la perm admin
    if not before.permissions.administrator and after.permissions.administrator:
        actor_id, entry = await resolve_audit_actor(
            after.guild, discord.AuditLogAction.role_update, target_id=after.id)
        if actor_id and actor_id != bot.user.id:
            await check_action_and_react(
                after.guild, actor_id, "role_grant_admin",
                target=after, target_name=after.name,
                revert_fn=revert_role_update_admin,
                revert_args=(after.id, before.permissions.value),
            )
            # Alerte critique supplémentaire
            em = critical_embed(
                "🚨 PERMISSION ADMIN AJOUTÉE À UN RÔLE",
                f"**Auteur :** <@{actor_id}>\n"
                f"**Rôle :** {after.mention} (`{after.id}`)",
            )
            await send_log_embed(after.guild, em)
        return  # On ne double-compte pas comme role_update

    # Update classique (nom, couleur, perms non-admin)
    if (before.name != after.name or
        before.color != after.color or
        before.permissions.value != after.permissions.value or
        before.mentionable != after.mentionable or
        before.hoist != after.hoist):
        actor_id, entry = await resolve_audit_actor(
            after.guild, discord.AuditLogAction.role_update, target_id=after.id)
        if actor_id is None or actor_id == bot.user.id:
            return
        await check_action_and_react(
            after.guild, actor_id, "role_update",
            target=after, target_name=after.name,
        )


# -------------------- SALONS --------------------

@bot.event
async def on_guild_channel_create(channel):
    actor_id, entry = await resolve_audit_actor(
        channel.guild, discord.AuditLogAction.channel_create, target_id=channel.id)
    if actor_id is None:
        return
    await check_action_and_react(
        channel.guild, actor_id, "channel_create",
        target=channel, target_name=channel.name,
        revert_fn=revert_channel_create, revert_args=(channel.id,),
    )


@bot.event
async def on_guild_channel_delete(channel):
    actor_id, entry = await resolve_audit_actor(
        channel.guild, discord.AuditLogAction.channel_delete, target_id=channel.id)
    if actor_id is None:
        return
    # Chercher le snapshot dans le dernier backup
    backup = get_latest_backup(channel.guild.id)
    channel_snapshot = None
    if backup and backup.get("channels"):
        for c in backup["channels"]:
            if c["id"] == str(channel.id):
                channel_snapshot = c
                break

    await check_action_and_react(
        channel.guild, actor_id, "channel_delete",
        target=channel, target_name=channel.name,
        revert_fn=revert_channel_delete if channel_snapshot else None,
        revert_args=(channel_snapshot,) if channel_snapshot else None,
    )


@bot.event
async def on_guild_channel_update(before, after):
    if before.name != after.name or before.position != after.position:
        actor_id, entry = await resolve_audit_actor(
            after.guild, discord.AuditLogAction.channel_update, target_id=after.id)
        if actor_id is None or actor_id == bot.user.id:
            return
        await check_action_and_react(
            after.guild, actor_id, "channel_update",
            target=after, target_name=after.name,
        )
    # Changement d'overwrites (perm override)
    if before.overwrites != after.overwrites:
        actor_id, entry = await resolve_audit_actor(
            after.guild, discord.AuditLogAction.overwrite_update, target_id=after.id)
        if actor_id is None or actor_id == bot.user.id:
            return
        await check_action_and_react(
            after.guild, actor_id, "overwrite_update",
            target=after, target_name=after.name,
        )


# -------------------- SERVEUR --------------------

@bot.event
async def on_guild_update(before, after):
    if (before.name != after.name or before.icon != after.icon or
        before.verification_level != after.verification_level):
        actor_id, entry = await resolve_audit_actor(
            after, discord.AuditLogAction.guild_update)
        if actor_id is None or actor_id == bot.user.id:
            return
        await check_action_and_react(
            after, actor_id, "guild_update",
            target=None, target_name=f"Serveur ({after.name})",
        )


@bot.event
async def on_webhooks_update(channel):
    """Un webhook a été créé, modifié ou supprimé dans ce salon."""
    # On cherche l'entrée la plus récente sur webhooks
    actor_id, entry = await resolve_audit_actor(
        channel.guild, discord.AuditLogAction.webhook_create, delay=1.0)
    if actor_id is None:
        actor_id, entry = await resolve_audit_actor(
            channel.guild, discord.AuditLogAction.webhook_delete, delay=1.0)
        if actor_id:
            await check_action_and_react(
                channel.guild, actor_id, "webhook_delete",
                target=channel, target_name=f"webhook in #{channel.name}",
            )
        return
    await check_action_and_react(
        channel.guild, actor_id, "webhook_create",
        target=channel, target_name=f"webhook in #{channel.name}",
    )


@bot.event
async def on_guild_emojis_update(guild, before, after):
    before_ids = {e.id for e in before}
    after_ids = {e.id for e in after}
    added = after_ids - before_ids
    removed = before_ids - after_ids

    if added:
        actor_id, entry = await resolve_audit_actor(
            guild, discord.AuditLogAction.emoji_create)
        if actor_id:
            await check_action_and_react(
                guild, actor_id, "emoji_create",
                target=None, target_name=f"{len(added)} emoji(s)",
            )
    if removed:
        actor_id, entry = await resolve_audit_actor(
            guild, discord.AuditLogAction.emoji_delete)
        if actor_id:
            await check_action_and_react(
                guild, actor_id, "emoji_delete",
                target=None, target_name=f"{len(removed)} emoji(s)",
            )


@bot.event
async def on_member_join(member):
    """Détecte l'ajout d'un bot au serveur."""
    if not member.bot:
        return

    # Si le bot vient d'être ajouté et qu'il est whitelist → rien à faire
    if wl_bot_is_whitelisted(member.guild.id, member.id):
        log.info(f"Bot whitelist {member} rejoint {member.guild.name}, bypass.")
        return

    # Chercher qui l'a ajouté via audit log
    actor_id, entry = await resolve_audit_actor(
        member.guild, discord.AuditLogAction.bot_add, target_id=member.id, delay=2.0)

    if actor_id is None:
        # Pas d'info sur l'auteur : on kick le bot par sécurité et on log
        log.warning(f"Bot {member} ajouté sur {member.guild.name} sans actor identifiable → kick préventif.")
        try:
            await member.kick(reason="mFast : bot non-whitelist ajouté (auteur inconnu)")
        except (discord.Forbidden, discord.HTTPException) as e:
            log.error(f"Kick bot sans auteur échoué : {e}")
        em = critical_embed(
            "🚨 BOT AJOUTÉ SANS AUTEUR IDENTIFIÉ",
            f"**Bot :** {member.mention} (`{member.id}`)\n"
            f"**Action :** kick préventif\n\n"
            f"Aucune entrée d'audit log claire pour identifier l'ajouteur."
        )
        await send_log_embed(member.guild, em)
        return

    # L'auteur est Buyer → il a le droit d'ajouter n'importe quel bot
    if is_buyer(actor_id):
        record_action(member.guild.id, actor_id, "bot_add",
                     target_id=member.id, target_name=f"Bot {member}",
                     details="Ajouté par Buyer")
        em = info_embed(
            "🤖 Bot ajouté par Buyer",
            f"**Bot :** {member.mention}\n"
            f"**Par :** <@{actor_id}>\n\n"
            f"⚠️ N'oublie pas de `{get_prefix_cached()}bot @{member.name}` pour le whitelister "
            f"(sinon ses futures actions pourraient déclencher le ban auto)."
        )
        await send_log_embed(member.guild, em)
        return

    # L'auteur N'EST PAS Buyer → BAN LE BOT + BAN L'AUTEUR
    # (Seul le Buyer peut ajouter des bots non-whitelist. Toute autre tentative = sabotage)

    log.warning(f"AJOUT BOT NON AUTORISÉ : {member} ajouté par {actor_id} sur {member.guild.name}")

    # Log d'action pour historique
    action_id = record_action(
        member.guild.id, actor_id, "bot_add",
        target_id=member.id, target_name=f"Bot {member}",
        details="AJOUT NON AUTORISÉ (non-Buyer)",
    )

    # 1. Ban le bot lui-même
    try:
        await member.ban(
            reason=f"mFast : bot non-whitelist ajouté par non-Buyer <@{actor_id}>",
            delete_message_seconds=0,
        )
        log.info(f"Bot {member.id} banni par mFast.")
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Ban du bot échoué : {e}")

    # 2. Ban la personne qui a ajouté le bot
    actor_member = member.guild.get_member(actor_id)
    actor_name = str(actor_member) if actor_member else f"ID {actor_id}"

    # DM best effort avant ban
    if actor_member:
        try:
            dm_em = discord.Embed(
                title="⛔ Tu as été banni automatiquement par mFast",
                description=(
                    f"Serveur : **{member.guild.name}**\n\n"
                    f"**Raison :** Tu as ajouté un bot non-whitelist (`{member.name}`) sur le serveur.\n\n"
                    f"Seul le **Buyer** peut ajouter un bot. Tu dois lui demander de whitelister "
                    f"le bot via `%bot` avant de l'inviter à nouveau.\n\n"
                    f"Cette décision est irrévocable sans intervention manuelle du Buyer."
                ),
                color=0xf04747,
            )
            dm_em.set_footer(text="mFast")
            await actor_member.send(embed=dm_em)
        except (discord.Forbidden, discord.HTTPException):
            pass

    try:
        await member.guild.ban(
            discord.Object(id=actor_id),
            reason=f"mFast : ajout de bot non-whitelist ({member.name})",
            delete_message_seconds=0,
        )
        log.info(f"Auteur {actor_id} banni par mFast pour ajout de bot non autorisé.")
    except (discord.Forbidden, discord.HTTPException) as e:
        log.error(f"Ban de l'auteur échoué : {e}")

    # Enregistre le ban auto
    ban_id = record_auto_ban(
        member.guild.id, actor_id, "bot_add",
        max_limit=0, window=0, count=1,
    )

    # Alerte critique
    em = critical_embed(
        "🚨 BOT NON AUTORISÉ + AJOUTEUR BANNIS",
        f"**Bot ajouté :** {member.mention} (`{member.id}`) → **BAN**\n"
        f"**Ajouté par :** <@{actor_id}> (`{actor_id}`) → **BAN**\n\n"
        f"Seul le **Buyer** est autorisé à ajouter des bots.\n"
        f"**Ban ID :** `#{ban_id}` ・ **Action ID :** `#{action_id}`\n\n"
        f"Pour réhabiliter l'auteur : `{get_prefix_cached()}unban <id>` (Sanction bot).\n"
        f"Pour autoriser ce bot à l'avenir : ajoute-le d'abord, puis `{get_prefix_cached()}bot @bot`."
    )
    await send_log_embed(member.guild, em)


# ========================= TÂCHES DE FOND =========================

@tasks.loop(minutes=BACKUP_INTERVAL_MIN)
async def backup_loop():
    """Backup auto de tous les serveurs toutes les 60min."""
    try:
        for guild in bot.guilds:
            await do_backup(guild, trigger="auto")
    except Exception as e:
        log.error(f"backup_loop erreur : {e}\n{traceback.format_exc()}")


@backup_loop.before_loop
async def _backup_before():
    await bot.wait_until_ready()


@tasks.loop(hours=12)
async def cleanup_loop():
    """Purge l'historique des actions > 30 jours."""
    try:
        cleanup_old_history()
        log.info("Cleanup historique effectué")
    except Exception as e:
        log.error(f"cleanup_loop erreur : {e}")


@cleanup_loop.before_loop
async def _cleanup_before():
    await bot.wait_until_ready()


# ════════════════════════════════════════════════════════════════════════════
#  PARTIE 3 — COMMANDES BUYER + HELP + RUN
# ════════════════════════════════════════════════════════════════════════════


# ========================= CONFIG DE BASE =========================

@bot.command(name="prefix")
async def _prefix(ctx, new_prefix: str = None):
    if not new_prefix:
        return await ctx.send(embed=info_embed("Prefix actuel", f"`{get_prefix_cached()}`"))
    set_config("prefix", new_prefix)
    await ctx.send(embed=success_embed("✅ Prefix modifié", f"Nouveau prefix : `{new_prefix}`"))


@bot.command(name="setlog")
async def _setlog(ctx, channel: discord.TextChannel = None):
    """Définit le salon de log global (fallback quand une action n'a pas de salon dédié)."""
    if channel is None:
        return await ctx.send(embed=error_embed("Usage", f"`{get_prefix_cached()}setlog #salon`"))
    set_log_channel(ctx.guild.id, channel.id)
    await ctx.send(embed=success_embed(
        "✅ Salon de logs défini",
        f"Les alertes mFast sans salon dédié iront dans {channel.mention}.\n"
        f"Pour un salon par type d'action, utilise `{get_prefix_cached()}categorie <id_categorie>`."
    ))


# ========================= CATÉGORIE DE LOGS =========================

@bot.command(name="categorie", aliases=["category"])
async def _categorie(ctx, category_input: str = None):
    """
    Définit une catégorie qui contiendra un salon de log par type d'action.
    Crée automatiquement tous les salons dedans.
    Usage : %categorie <id_categorie>  ou  %categorie <mention_ou_nom>
    """
    if category_input is None:
        # Affichage statut
        current = get_log_category(ctx.guild.id)
        if not current:
            return await ctx.send(embed=info_embed(
                "📂 Catégorie de logs",
                f"Aucune catégorie définie.\n\n"
                f"Usage : `{get_prefix_cached()}categorie <id_catégorie>`\n"
                f"Je vais créer un salon par type d'action dans cette catégorie."
            ))
        category = ctx.guild.get_channel(int(current["category_id"]))
        channels_map = get_all_action_channels(ctx.guild.id)
        cat_display = category.mention if category else f"`{current['category_id']}`"
        em = info_embed(
            "📂 Catégorie de logs",
            f"**Catégorie :** {cat_display}\n"
            f"**Salons configurés :** {len(channels_map)} / {len(WATCHED_ACTIONS)}\n"
            f"**Définie le :** {format_datetime(current.get('set_at'))}\n"
            f"**Par :** <@{current.get('set_by')}>"
        )
        if channels_map:
            lines = []
            for action, ch_id in list(channels_map.items())[:15]:
                ch = ctx.guild.get_channel(int(ch_id))
                lines.append(f"• `{action}` → {ch.mention if ch else '*supprimé*'}")
            if len(channels_map) > 15:
                lines.append(f"*... et {len(channels_map) - 15} autres*")
            em.add_field(name="Mapping", value="\n".join(lines), inline=False)
        return await ctx.send(embed=em)

    # Résolution de la catégorie
    clean = category_input.strip("<#>")
    category = None
    try:
        cat_id = int(clean)
        category = ctx.guild.get_channel(cat_id)
    except ValueError:
        # Recherche par nom
        for c in ctx.guild.categories:
            if c.name.lower() == clean.lower():
                category = c
                break

    if not category or not isinstance(category, discord.CategoryChannel):
        return await ctx.send(embed=error_embed(
            "❌ Catégorie introuvable",
            "Passe l'**ID** d'une catégorie existante ou son nom exact.\n"
            "Clique droit sur la catégorie → Copier l'identifiant."
        ))

    # Confirmation visuelle du début
    msg = await ctx.send(embed=info_embed(
        "⏳ Configuration en cours...",
        f"Création des salons de log dans **{category.name}**.\n"
        f"Je vais créer **{len(WATCHED_ACTIONS)}** salons. Ça peut prendre ~30s à cause des rate limits."
    ))

    # Enregistre la catégorie
    set_log_category(ctx.guild.id, category.id, ctx.author.id)

    # Vide l'ancien mapping s'il y en avait un
    clear_action_channels(ctx.guild.id)

    # Permissions : seul le bot peut écrire, tout le monde peut lire (admin voit tout)
    # On met @everyone en read-only et on s'assure que le bot peut envoyer
    overwrites = {
        ctx.guild.default_role: discord.PermissionOverwrite(
            view_channel=True, send_messages=False, read_message_history=True,
        ),
        ctx.guild.me: discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True,
            manage_channels=True, embed_links=True,
        ),
    }

    created = 0
    errors = []

    # Regroupement logique pour nommer les salons (court et clair)
    channel_names = {
        # Membres
        "ban":                "logs-ban",
        "unban":              "logs-unban",
        "kick":               "logs-kick",
        "timeout":            "logs-timeout",
        "vdisconnect":        "logs-voc-deco",
        "vmove":              "logs-voc-move",
        "member_role_add":    "logs-role-add",
        "member_role_remove": "logs-role-remove",
        "member_nick":        "logs-pseudo",
        # Rôles
        "role_create":        "logs-role-create",
        "role_delete":        "logs-role-delete",
        "role_update":        "logs-role-update",
        "role_grant_admin":   "logs-admin-grant",
        # Salons
        "channel_create":     "logs-salon-create",
        "channel_delete":     "logs-salon-delete",
        "channel_update":     "logs-salon-update",
        "overwrite_update":   "logs-overwrites",
        # Serveur
        "guild_update":       "logs-serveur",
        "webhook_create":     "logs-webhook-create",
        "webhook_delete":     "logs-webhook-delete",
        "emoji_create":       "logs-emoji-create",
        "emoji_delete":       "logs-emoji-delete",
        "bot_add":            "logs-bot-add",
    }

    for action in WATCHED_ACTIONS.keys():
        name = channel_names.get(action, f"logs-{action}")
        try:
            new_ch = await ctx.guild.create_text_channel(
                name=name,
                category=category,
                overwrites=overwrites,
                topic=f"mFast : logs pour l'action `{action}` ({WATCHED_ACTIONS[action]})",
                reason=f"mFast setup catégorie par {ctx.author}",
            )
            set_action_channel(ctx.guild.id, action, new_ch.id)
            created += 1
            # Petit délai pour éviter rate limit Discord
            await asyncio.sleep(0.6)
        except discord.Forbidden as e:
            errors.append(f"`{action}` : permission refusée")
            log.error(f"categorie: {action} échoué (Forbidden) : {e}")
        except discord.HTTPException as e:
            errors.append(f"`{action}` : {e}")
            log.error(f"categorie: {action} échoué : {e}")

    # Résultat
    try:
        await msg.delete()
    except discord.HTTPException:
        pass

    em = success_embed(
        "✅ Catégorie configurée",
        f"**Catégorie :** {category.mention}\n"
        f"**Salons créés :** {created} / {len(WATCHED_ACTIONS)}\n"
        + (f"**Erreurs :** {len(errors)}" if errors else "")
    )
    if errors:
        em.add_field(
            name="Erreurs",
            value="\n".join(errors[:10]) + (f"\n*+{len(errors)-10} autres*" if len(errors) > 10 else ""),
            inline=False,
        )
    em.add_field(
        name="ℹ️ Fonctionnement",
        value=(
            "Chaque action détectée ira dans son salon dédié avec :\n"
            "• **Ping** de l'auteur\n"
            "• **Quota restant** avant limite\n"
            "• **Timestamp** complet"
        ),
        inline=False,
    )
    await ctx.send(embed=em)


@bot.command(name="uncategorie", aliases=["uncategory"])
async def _uncategorie(ctx, delete_channels: str = None):
    """
    Retire la catégorie de logs.
    %uncategorie        → retire juste le mapping (garde les salons)
    %uncategorie delete → retire le mapping ET supprime tous les salons créés
    """
    current = get_log_category(ctx.guild.id)
    if not current:
        return await ctx.send(embed=error_embed("Aucune catégorie", "Il n'y a pas de catégorie de logs configurée."))

    channels_map = get_all_action_channels(ctx.guild.id)
    delete = delete_channels and delete_channels.lower() in ("delete", "suppr", "suppression")

    deleted_count = 0
    if delete:
        for action, ch_id in channels_map.items():
            ch = ctx.guild.get_channel(int(ch_id))
            if ch:
                try:
                    await ch.delete(reason=f"mFast uncategorie delete par {ctx.author}")
                    deleted_count += 1
                    await asyncio.sleep(0.4)
                except (discord.Forbidden, discord.HTTPException) as e:
                    log.warning(f"uncategorie: suppression {ch.name} échouée : {e}")

    # Purger en DB
    conn = get_db()
    conn.execute("DELETE FROM log_category WHERE guild_id = ?", (str(ctx.guild.id),))
    conn.commit()
    conn.close()
    clear_action_channels(ctx.guild.id)

    em = success_embed(
        "✅ Catégorie de logs retirée",
        f"**Mapping supprimé :** {len(channels_map)} actions"
        + (f"\n**Salons supprimés :** {deleted_count}" if delete else
           "\n*Les salons existants ont été conservés.*")
    )
    await ctx.send(embed=em)


# ========================= RANGS =========================

@bot.command(name="wl")
async def _wl(ctx, *, user_input: str = None):
    if user_input is None:
        ids = get_ranks_by_level(1)
        if not ids:
            return await ctx.send(embed=info_embed("📋 Liste WL", "Aucun WL."))
        return await ctx.send(embed=info_embed(
            f"📋 WL ({len(ids)})",
            "\n".join([f"<@{uid}>" for uid in ids])
        ))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    if get_rank(uid) >= 1:
        return await ctx.send(embed=error_embed("Déjà rang", f"{format_user_display(display, uid)} a déjà un rang."))
    set_rank(uid, 1)
    await ctx.send(embed=success_embed(
        "✅ WL ajouté",
        f"{format_user_display(display, uid)} est maintenant **WL**."
    ))


@bot.command(name="unwl")
async def _unwl(ctx, *, user_input: str = None):
    if not user_input:
        return await ctx.send(embed=error_embed("Argument manquant", "Mention, ID ou nom requis."))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    if get_rank(uid) != 1:
        return await ctx.send(embed=error_embed("Pas WL", f"{format_user_display(display, uid)} n'est pas WL."))
    set_rank(uid, 0)
    await ctx.send(embed=success_embed("✅ WL retiré", f"{format_user_display(display, uid)} n'est plus WL."))


@bot.command(name="owner")
async def _owner(ctx, *, user_input: str = None):
    if user_input is None:
        ids = get_ranks_by_level(2)
        if not ids:
            return await ctx.send(embed=info_embed("📋 Liste Owner", "Aucun Owner."))
        return await ctx.send(embed=info_embed(
            f"📋 Owner ({len(ids)})",
            "\n".join([f"<@{uid}>" for uid in ids])
        ))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    if get_rank(uid) >= 2:
        return await ctx.send(embed=error_embed("Déjà rang", f"{format_user_display(display, uid)} a déjà un rang ≥ 2."))
    set_rank(uid, 2)
    await ctx.send(embed=success_embed(
        "✅ Owner ajouté",
        f"{format_user_display(display, uid)} est maintenant **Owner**."
    ))


@bot.command(name="unowner")
async def _unowner(ctx, *, user_input: str = None):
    if not user_input:
        return await ctx.send(embed=error_embed("Argument manquant", "Mention, ID ou nom requis."))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    if get_rank(uid) != 2:
        return await ctx.send(embed=error_embed("Pas Owner", f"{format_user_display(display, uid)} n'est pas Owner."))
    set_rank(uid, 0)
    await ctx.send(embed=success_embed("✅ Owner retiré", f"{format_user_display(display, uid)} n'est plus Owner."))


@bot.command(name="sys")
async def _sys(ctx, *, user_input: str = None):
    if user_input is None:
        ids = get_ranks_by_level(3)
        if not ids:
            return await ctx.send(embed=info_embed("📋 Liste Sys", "Aucun Sys."))
        return await ctx.send(embed=info_embed(
            f"📋 Sys ({len(ids)})",
            "\n".join([f"<@{uid}>" for uid in ids])
        ))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    if get_rank(uid) >= 3:
        return await ctx.send(embed=error_embed("Déjà rang", f"{format_user_display(display, uid)} a déjà un rang ≥ 3."))
    set_rank(uid, 3)
    await ctx.send(embed=success_embed(
        "✅ Sys ajouté",
        f"{format_user_display(display, uid)} est maintenant **Sys**."
    ))


@bot.command(name="unsys")
async def _unsys(ctx, *, user_input: str = None):
    if not user_input:
        return await ctx.send(embed=error_embed("Argument manquant", "Mention, ID ou nom requis."))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    if get_rank(uid) != 3:
        return await ctx.send(embed=error_embed("Pas Sys", f"{format_user_display(display, uid)} n'est pas Sys."))
    set_rank(uid, 0)
    await ctx.send(embed=success_embed("✅ Sys retiré", f"{format_user_display(display, uid)} n'est plus Sys."))


# ========================= BOTS WHITELIST =========================

@bot.command(name="bot")
async def _bot(ctx, *, user_input: str = None):
    """Ajoute un bot à la whitelist. Bypass total."""
    if user_input is None:
        return await ctx.send(embed=error_embed(
            "Usage",
            f"`{get_prefix_cached()}bot <@bot|id>`\n\n"
            f"Le bot whitelisté pourra faire **toutes les actions** sans être sanctionné.\n\n"
            f"⚠️ **Attention :** ne whitelist qu'un bot de confiance."
        ))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    is_a_bot = False
    bot_name = None
    if display:
        is_a_bot = getattr(display, "bot", False)
        bot_name = getattr(display, "name", None) or str(display)
    if not is_a_bot:
        try:
            fetched = await bot.fetch_user(uid)
            is_a_bot = fetched.bot
            bot_name = fetched.name
        except (discord.NotFound, discord.HTTPException):
            pass
    if not is_a_bot:
        return await ctx.send(embed=error_embed(
            "❌ Pas un bot",
            f"{format_user_display(display, uid)} n'est pas un compte bot."
        ))
    if wl_bot_is_whitelisted(ctx.guild.id, uid):
        return await ctx.send(embed=error_embed("Déjà whitelist", f"Le bot **{bot_name}** est déjà whitelisté."))
    wl_bot_add(ctx.guild.id, uid, bot_name or "?", ctx.author.id)
    await ctx.send(embed=success_embed(
        "✅ Bot whitelisté",
        f"🤖 **{bot_name}** (`{uid}`) bypass maintenant toutes les limites mFast."
    ))


@bot.command(name="unbot")
async def _unbot(ctx, *, user_input: str = None):
    if not user_input:
        return await ctx.send(embed=error_embed("Argument manquant", "Mention, ID ou nom requis."))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    if not wl_bot_is_whitelisted(ctx.guild.id, uid):
        return await ctx.send(embed=error_embed("Pas whitelist", f"{format_user_display(display, uid)} n'est pas whitelist."))
    wl_bot_remove(ctx.guild.id, uid)
    bot_name = getattr(display, "name", None) or f"ID {uid}"
    await ctx.send(embed=success_embed("✅ Bot retiré", f"🤖 **{bot_name}** n'est plus whitelisté."))


@bot.command(name="bots")
async def _bots(ctx):
    rows = wl_bot_list(ctx.guild.id)
    if not rows:
        return await ctx.send(embed=info_embed(
            "🤖 Aucun bot whitelisté",
            f"Utilise `{get_prefix_cached()}bot @bot` pour en ajouter."
        ))
    lines = []
    for r in rows:
        lines.append(
            f"🤖 <@{r['bot_user_id']}> (`{r['bot_user_id']}`)\n"
            f"   ↳ ajouté par <@{r['added_by']}> le {format_datetime(r['added_at'])}"
        )
    em = info_embed(f"🤖 Bots whitelistés ({len(rows)})", "\n\n".join(lines))
    await ctx.send(embed=em)


@bot.command(name="perms")
async def _perms(ctx):
    wls = get_ranks_by_level(1)
    owners = get_ranks_by_level(2)
    syss = get_ranks_by_level(3)
    buyer_ids_raw = get_config("buyer_ids")
    buyers = json.loads(buyer_ids_raw) if buyer_ids_raw else []
    bots_wl = wl_bot_list(ctx.guild.id)
    lines = []
    lines.append(f"**👑 Buyer ({len(buyers)})** : " + (", ".join(f"<@{uid}>" for uid in buyers) if buyers else "*aucun*"))
    lines.append(f"**🔧 Sys ({len(syss)})** : " + (", ".join(f"<@{uid}>" for uid in syss) if syss else "*aucun*"))
    lines.append(f"**⚔️ Owner ({len(owners)})** : " + (", ".join(f"<@{uid}>" for uid in owners) if owners else "*aucun*"))
    lines.append(f"**🛡️ WL ({len(wls)})** : " + (", ".join(f"<@{uid}>" for uid in wls) if wls else "*aucun*"))
    lines.append(f"**🤖 Bots whitelist ({len(bots_wl)})** : " +
                (", ".join(f"<@{b['bot_user_id']}>" for b in bots_wl) if bots_wl else "*aucun*"))
    em = info_embed("📋 Permissions configurées", "\n".join(lines))
    await ctx.send(embed=em)


# ========================= LIMITES =========================

@bot.command(name="setlimit")
async def _setlimit(ctx, action: str = None, rank_str: str = None,
                    max_actions: int = None, window_minutes: int = None):
    if action is None or rank_str is None or max_actions is None or window_minutes is None:
        return await ctx.send(embed=error_embed(
            "Usage",
            f"`{get_prefix_cached()}setlimit <action> <rang> <max> <minutes>`\n\n"
            f"**Ex :** `{get_prefix_cached()}setlimit ban wl 3 20` → WL: 3 bans / 20min\n"
            f"**Rangs :** `wl`, `owner`, `sys` (Buyer illimité)\n"
            f"**Actions :** voir `{get_prefix_cached()}actions`"
        ))
    action = action.lower().strip()
    if action not in WATCHED_ACTIONS:
        return await ctx.send(embed=error_embed("❌ Action inconnue", f"Voir `{get_prefix_cached()}actions`."))
    rank_map = {"wl": 1, "owner": 2, "sys": 3}
    if rank_str.lower() not in rank_map:
        return await ctx.send(embed=error_embed("❌ Rang", "`wl`, `owner` ou `sys`."))
    rank = rank_map[rank_str.lower()]
    if max_actions < 0 or max_actions > 1000:
        return await ctx.send(embed=error_embed("❌ Max", "Entre 0 et 1000."))
    if window_minutes < 0 or window_minutes > 10080:
        return await ctx.send(embed=error_embed("❌ Fenêtre", "Entre 0 et 10080min."))
    set_limit(action, rank, max_actions, window_minutes)
    desc = "**Interdit**" if max_actions == 0 else f"max **{max_actions}** / **{window_minutes}min**"
    await ctx.send(embed=success_embed(
        "✅ Limite configurée",
        f"`{action}` pour **{rank_name(rank)}** : {desc}"
    ))


@bot.command(name="unsetlimit")
async def _unsetlimit(ctx, action: str = None, rank_str: str = None):
    if action is None or rank_str is None:
        return await ctx.send(embed=error_embed("Usage", f"`{get_prefix_cached()}unsetlimit <action> <rang>`"))
    rank_map = {"wl": 1, "owner": 2, "sys": 3}
    if rank_str.lower() not in rank_map:
        return await ctx.send(embed=error_embed("❌ Rang", "`wl`, `owner` ou `sys`."))
    rank = rank_map[rank_str.lower()]
    if not remove_limit(action.lower(), rank):
        return await ctx.send(embed=error_embed("Pas de limite", f"Pas de limite pour `{action}` au rang {rank_name(rank)}."))
    await ctx.send(embed=warning_embed(
        "⚠️ Limite retirée",
        f"Sans limite configurée, `{action}` devient **interdit** pour {rank_name(rank)} par défaut."
    ))


@bot.command(name="limits")
async def _limits(ctx):
    limits = get_limits()
    if not limits:
        return await ctx.send(embed=info_embed("Aucune limite", "Rien à afficher."))
    rank_emoji = {1: "🛡️", 2: "⚔️", 3: "🔧"}
    lines = []
    for action in sorted(limits.keys()):
        lines.append(f"\n**`{action}`** — {WATCHED_ACTIONS.get(action, '')}")
        for rank_num in sorted(limits[action].keys()):
            max_a, window = limits[action][rank_num]
            val = "❌ interdit" if max_a == 0 else f"**{max_a}** / **{window}min**"
            lines.append(f"  {rank_emoji.get(rank_num, '•')} {rank_name(rank_num)} : {val}")
    full = "\n".join(lines)
    if len(full) > 4000:
        chunks = [full[i:i+4000] for i in range(0, len(full), 4000)]
        for i, chunk in enumerate(chunks):
            await ctx.send(embed=info_embed(f"⏱️ Limites ({i+1}/{len(chunks)})", chunk))
    else:
        em = info_embed("⏱️ Limites", full)
        em.set_footer(text=f"mFast ・ Buyer illimité ・ {get_prefix_cached()}setlimit pour modifier")
        await ctx.send(embed=em)


@bot.command(name="actions")
async def _actions(ctx):
    lines = [f"• `{a}` — {d}" for a, d in sorted(WATCHED_ACTIONS.items())]
    em = info_embed(f"🔍 Actions surveillées ({len(WATCHED_ACTIONS)})", "\n".join(lines))
    await ctx.send(embed=em)


# ========================= BACKUPS =========================

@bot.command(name="backup")
async def _backup(ctx):
    """Force un backup manuel."""
    backup_id, err = await do_backup(ctx.guild, trigger="manual")
    if backup_id:
        await ctx.send(embed=success_embed(
            "✅ Backup effectué",
            f"Backup `#{backup_id}` sauvegardé."
        ))
    else:
        await ctx.send(embed=error_embed(
            "❌ Backup échoué",
            f"**Erreur :** `{err or 'inconnue'}`\n\n"
            f"*Le détail complet est dans les logs du bot (stdout).*"
        ))


@bot.command(name="backuplist", aliases=["backups"])
async def _backuplist(ctx):
    backups = list_backups(ctx.guild.id)
    if not backups:
        return await ctx.send(embed=info_embed("Aucun backup", "Aucun backup."))
    trigger_emoji = {"auto": "🔄", "manual": "✋", "startup": "🚀"}
    lines = []
    for b in backups:
        emoji = trigger_emoji.get(b["trigger"], "📦")
        lines.append(f"{emoji} `#{b['id']}` ・ {format_datetime(b['created_at'])} ・ *{b['trigger']}*")
    em = info_embed(f"📦 Backups ({len(backups)})", "\n".join(lines))
    em.set_footer(text="mFast ・ Revert auto en cas d'abus (pas de commande manuelle)")
    await ctx.send(embed=em)


# ========================= HISTORY =========================

@bot.command(name="history")
async def _history(ctx, *, user_input: str = None):
    if user_input:
        display, uid = await resolve_user_or_id(ctx, user_input)
        if uid is None:
            return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", ""))
        rows = get_user_history(uid, ctx.guild.id, limit=25)
        title = f"📜 Historique de {display.display_name if display else f'ID {uid}'}"
    else:
        rows = get_recent_actions(ctx.guild.id, limit=25)
        title = "📜 Historique global"
    if not rows:
        return await ctx.send(embed=info_embed(title, "Aucune action enregistrée."))
    lines = []
    for r in rows:
        reverted_mark = " ↩️" if r.get("reverted") else ""
        target_str = f" → {r['target_name']}" if r.get("target_name") else ""
        details = f" *{r['details']}*" if r.get("details") else ""
        lines.append(f"`{format_datetime(r['created_at'])}` <@{r['user_id']}> ・ `{r['action']}`{target_str}{details}{reverted_mark}")
    full = "\n".join(lines)
    if len(full) > 4000:
        full = full[:4000] + "\n..."
    em = info_embed(title, full)
    em.set_footer(text=f"mFast ・ {len(rows)} entrées")
    await ctx.send(embed=em)


@bot.command(name="autobans")
async def _autobans(ctx):
    rows = get_recent_auto_bans(ctx.guild.id, limit=20)
    if not rows:
        return await ctx.send(embed=info_embed("🔒 Bans auto", "Aucun."))
    lines = []
    for r in rows:
        lines.append(
            f"`{format_datetime(r['banned_at'])}` ・ <@{r['user_id']}> ・ "
            f"`{r['action_trigger']}` ({r['actions_count']}/{r['limit_max']} en {r['limit_window']}min)"
        )
    em = info_embed(f"🔒 Bans auto ({len(rows)})", "\n".join(lines))
    await ctx.send(embed=em)


# ========================= LOCKDOWN =========================

@bot.command(name="lockdown")
async def _lockdown(ctx, state: str = None):
    """%lockdown on/off — retire Admin aux rôles non-Sys+."""
    current = get_lockdown_state(ctx.guild.id)
    if state is None:
        status = "🟢 **Activé**" if current and current["enabled"] else "⚪ Désactivé"
        em = info_embed("🔒 Lockdown", f"Statut : {status}")
        if current and current["enabled"]:
            em.add_field(name="Depuis", value=format_datetime(current["enabled_at"]), inline=True)
            em.add_field(name="Par", value=f"<@{current['enabled_by']}>", inline=True)
        return await ctx.send(embed=em)
    state = state.lower().strip()
    if state not in ("on", "off"):
        return await ctx.send(embed=error_embed("❌ Valeur", "`on` ou `off`."))
    if state == "on":
        if current and current["enabled"]:
            return await ctx.send(embed=error_embed("Déjà actif", "Déjà activé."))
        saved = {}
        changed = []
        sys_ids = set(get_ranks_by_level(3)) | set(get_ranks_by_level(4))
        sys_role_ids = set()
        for mid in sys_ids:
            m = ctx.guild.get_member(int(mid))
            if m:
                for r in m.roles:
                    if r.permissions.administrator:
                        sys_role_ids.add(r.id)
        for role in ctx.guild.roles:
            if role.is_default() or role.managed or role.id in sys_role_ids:
                continue
            if role.permissions.administrator:
                saved[str(role.id)] = role.permissions.value
                try:
                    np = discord.Permissions(role.permissions.value)
                    np.administrator = False
                    await role.edit(permissions=np, reason=f"mFast lockdown par {ctx.author}")
                    changed.append(role.name)
                    await asyncio.sleep(0.3)
                except (discord.Forbidden, discord.HTTPException) as e:
                    log.error(f"Lockdown : {role.name} : {e}")
        set_lockdown(ctx.guild.id, True, ctx.author.id, saved)
        await ctx.send(embed=critical_embed(
            "🔒 LOCKDOWN ACTIVÉ",
            f"**{len(changed)}** rôles ont perdu Admin.\nSeuls les Sys+ conservent leurs droits."
        ))
    else:
        if not current or not current["enabled"]:
            return await ctx.send(embed=error_embed("Pas actif", "Lockdown désactivé."))
        saved_perms = {}
        if current.get("saved_perms"):
            try:
                saved_perms = json.loads(current["saved_perms"])
            except (json.JSONDecodeError, TypeError):
                pass
        restored = []
        for role_id, perms in saved_perms.items():
            role = ctx.guild.get_role(int(role_id))
            if role:
                try:
                    await role.edit(permissions=discord.Permissions(int(perms)),
                                   reason=f"mFast lockdown off par {ctx.author}")
                    restored.append(role.name)
                    await asyncio.sleep(0.3)
                except (discord.Forbidden, discord.HTTPException) as e:
                    log.error(f"Lockdown off : {role_id} : {e}")
        set_lockdown(ctx.guild.id, False)
        await ctx.send(embed=success_embed(
            "🔓 Lockdown désactivé",
            f"**{len(restored)}** rôles restaurés."
        ))


# ========================= PANIC =========================

_pending_panic = {}


@bot.command(name="panic")
async def _panic(ctx):
    """Mode panique : ban les non-WL actifs dans les 5 dernières minutes."""
    await ctx.send(embed=warning_embed(
        "⚠️ MODE PANIQUE",
        f"Tu vas bannir **tous les non-WL** ayant fait une action dans les 5 dernières minutes.\n\n"
        f"Les Buyer/Sys/Owner/WL/bots whitelist sont **épargnés**.\n\n"
        f"Tape `{get_prefix_cached()}panicconfirm` dans les 30s pour valider."
    ))
    _pending_panic[ctx.author.id] = {
        "guild_id": ctx.guild.id,
        "expires": datetime.now(PARIS_TZ) + timedelta(seconds=30),
    }


@bot.command(name="panicconfirm")
async def _panicconfirm(ctx):
    pending = _pending_panic.get(ctx.author.id)
    if not pending:
        return await ctx.send(embed=error_embed("❌ Aucune demande", f"Fais `{get_prefix_cached()}panic` d'abord."))
    if pending["expires"] < datetime.now(PARIS_TZ):
        del _pending_panic[ctx.author.id]
        return await ctx.send(embed=error_embed("❌ Expiré", ""))
    if pending["guild_id"] != ctx.guild.id:
        return await ctx.send(embed=error_embed("❌ Mauvais serveur", ""))
    del _pending_panic[ctx.author.id]
    conn = get_db()
    cutoff = (datetime.now(PARIS_TZ) - timedelta(minutes=5)).isoformat()
    rows = conn.execute("""SELECT DISTINCT user_id FROM action_history
        WHERE guild_id = ? AND created_at >= ?""",
        (str(ctx.guild.id), cutoff)).fetchall()
    conn.close()
    suspect_ids = [r["user_id"] for r in rows]
    banned = 0
    skipped = 0
    for uid_str in suspect_ids:
        uid = int(uid_str)
        if is_whitelisted(uid) or wl_bot_is_whitelisted(ctx.guild.id, uid):
            skipped += 1
            continue
        try:
            await ctx.guild.ban(discord.Object(id=uid),
                               reason=f"mFast PANIC par {ctx.author}",
                               delete_message_seconds=0)
            banned += 1
            await asyncio.sleep(0.2)
        except (discord.Forbidden, discord.HTTPException) as e:
            log.error(f"Panic ban {uid} : {e}")
    await ctx.send(embed=critical_embed(
        "🚨 PANIC EXÉCUTÉ",
        f"**Bannis :** {banned}\n**Épargnés :** {skipped}"
    ))


# ========================= HELP =========================

@bot.command(name="help")
async def _help(ctx):
    p = get_prefix_cached()
    em = discord.Embed(
        title="🛡️ mFast — Anti-nuke serveur",
        color=embed_color(),
    )
    em.description = (
        f"```\n🕐  {format_french_date()}\n```\n"
        f"**Prefix :** `{p}` ・ **Accès :** Buyer uniquement\n\n"
        f"mFast protège le serveur en surveillant toutes les actions sensibles via les audit logs.\n"
        f"**Tout abus** (non-whitelist ou limite dépassée) → **ban automatique + revert automatique**.\n\n"
        f"Les **bots** (Voice Master, Sanction, etc.) peuvent être whitelistés via `{p}bot @bot`."
    )

    em.add_field(
        name="📂 Catégorie de logs",
        value=(
            f"`{p}categorie <id_categorie>` — crée un salon par type d'action\n"
            f"`{p}categorie` — voir la config actuelle\n"
            f"`{p}uncategorie [delete]` — retirer (+ supprimer les salons si `delete`)"
        ),
        inline=False,
    )

    em.add_field(
        name="👥 Rangs",
        value=(
            f"`{p}wl @u` / `{p}unwl @u` — WL (limites strictes)\n"
            f"`{p}owner @u` / `{p}unowner @u` — Owner (limites moyennes)\n"
            f"`{p}sys @u` / `{p}unsys @u` — Sys (limites élevées)\n"
            f"`{p}perms` — liste tous les rangs"
        ),
        inline=False,
    )

    em.add_field(
        name="🤖 Bots whitelistés (bypass total)",
        value=(
            f"`{p}bot @bot` — whitelist un bot (bypass infini)\n"
            f"`{p}unbot @bot` — retirer\n"
            f"`{p}bots` — liste"
        ),
        inline=False,
    )

    em.add_field(
        name="⏱️ Limites",
        value=(
            f"`{p}actions` — actions surveillées\n"
            f"`{p}limits` — voir les limites\n"
            f"`{p}setlimit <action> <rang> <max> <min>` — configurer\n"
            f"`{p}unsetlimit <action> <rang>` — retirer"
        ),
        inline=False,
    )

    em.add_field(
        name="📦 Backups (auto toutes les 60min)",
        value=(
            f"`{p}backup` — backup manuel\n"
            f"`{p}backuplist` — voir les backups\n"
            f"*Le revert est **automatique** en cas d'abus. Pas de commande manuelle.*"
        ),
        inline=False,
    )

    em.add_field(
        name="🚨 Actions d'urgence",
        value=(
            f"`{p}lockdown on/off` — retire Admin aux rôles non-Sys+\n"
            f"`{p}panic` → `{p}panicconfirm` — ban les non-WL actifs"
        ),
        inline=False,
    )

    em.add_field(
        name="📜 Suivi",
        value=(
            f"`{p}history [@u]` — historique des actions\n"
            f"`{p}autobans` — bans auto récents"
        ),
        inline=False,
    )

    em.add_field(
        name="⚙️ Config",
        value=(
            f"`{p}setlog #salon` — salon log global (fallback)\n"
            f"`{p}prefix [nouveau]` — changer le prefix"
        ),
        inline=False,
    )

    em.set_footer(text="mFast ・ Meira")
    await ctx.send(embed=em)


# ========================= RUN =========================

if __name__ == "__main__":
    try:
        log.info("Démarrage de mFast...")
        bot.run(BOT_TOKEN, log_handler=None)
    except KeyboardInterrupt:
        log.info("Arrêt demandé par l'utilisateur.")
    except Exception as e:
        log.error(f"Erreur fatale : {e}", exc_info=True)
        sys.exit(1)
