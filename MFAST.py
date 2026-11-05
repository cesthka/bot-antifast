"""
================================================================================
  BOT ANTIFAST — Anti-nuke serveur (successeur de mFast)
================================================================================
Même système / même DA que le Bot BL :
  - Hiérarchie : Buyer (4) > Sys (3) > Owner (2) > Whitelist (1) > Aucun (0)
  - Embeds sombres, help filtré par rang (menu déroulant), panneaux interactifs

Fonctionnement :
  - Détection TEMPS RÉEL via l'événement audit log (on_audit_log_entry_create) :
    pas d'attente ni de lecture des audit logs, aucun mauvais auteur.
  - Chaque action sensible est comptée par rang (max / fenêtre glissante).
    Aucun rang = toute action surveillée est interdite (le staff doit être WL+).
  - Dépassement / action interdite / atteinte à la hiérarchie / au bot :
      -> sanction de l'auteur (ban, kick ou derank) — repli derank si le ban échoue
      -> revert de l'action ET de toutes ses actions des 30 dernières minutes
  - Reverts : salons/rôles recréés (position, catégorie, perms, enfants, membres),
    modifications de rôles/salons/perms/serveur annulées, webhooks supprimés,
    bans/unbans/timeouts annulés, vanity URL restaurée, emojis recréés,
    bots ajoutés bannis.
  - Backups auto + restauration complète (rôles, salons, perms, membres).
  - Lockdown (retrait des perms dangereuses), panic (ban des auteurs récents).

Variables d'environnement : TOKEN (ou TOKEN_MFAST), DATA_DIR
Portail dev : activer SERVER MEMBERS, MESSAGE CONTENT, PRESENCE.
Permissions du bot : Administrateur recommandé (au minimum : Voir les logs
d'audit, Bannir, Expulser, Exclure temporairement, Gérer les rôles, Gérer les
salons, Gérer le serveur, Gérer les webhooks, Gérer les expressions).
Le rôle du bot doit être LE PLUS HAUT possible dans la liste des rôles.
================================================================================
"""

import discord
from discord.ext import commands, tasks
import os
import sys
import json
import time
import base64
import asyncio
import sqlite3
import logging
import traceback
from collections import defaultdict, deque
from datetime import datetime, timezone

# ========================= CONFIG =========================
BOT_TOKEN = os.environ.get("TOKEN") or os.environ.get("TOKEN_MFAST")
if not BOT_TOKEN:
    print("[ERREUR CRITIQUE] La variable d'environnement TOKEN n'est pas définie.")
    sys.exit(1)

DEFAULT_BUYER_IDS = [142365250803466240]
DEFAULT_PREFIX = "%"

DATA_DIR = os.environ.get("DATA_DIR")
if not DATA_DIR:
    print("[ERREUR CRITIQUE] DATA_DIR non défini. Configure DATA_DIR=/data dans Railway.")
    sys.exit(1)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "antifast.db")

BACKUP_INTERVAL_MIN = 10       # backup auto toutes les X minutes
MAX_BACKUPS_PER_GUILD = 6      # nb de backups gardés par serveur
ACTION_HISTORY_DAYS = 30       # purge de l'historique
RECENT_REVERT_WINDOW = 1800    # à la sanction, on annule les actions des 30 dernières minutes
PUNISH_COOLDOWN = 30           # pas de double sanction pour le même auteur dans ce délai
MAX_ROLE_REASSIGN = 1000       # nb max de membres à qui on redonne un rôle recréé

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%d/%m/%Y %H:%M:%S")
log = logging.getLogger("antifast")

_prefix_cache = {"value": None}


# ========================= ACTIONS SURVEILLÉES =========================
# key: (label, emoji, groupe)
ACTIONS = {
    "ban":              ("Bannir un membre",              "🔨", "membres"),
    "unban":            ("Débannir un membre",            "🔓", "membres"),
    "kick":             ("Expulser un membre",            "👢", "membres"),
    "timeout":          ("Timeout un membre",             "⏳", "membres"),
    "prune":            ("Prune (kick de masse)",         "🧹", "membres"),
    "vdisconnect":      ("Déconnecter d'un vocal",        "🔇", "membres"),
    "vmove":            ("Déplacer en vocal",             "🔀", "membres"),
    "role_create":      ("Créer un rôle",                 "➕", "roles"),
    "role_delete":      ("Supprimer un rôle",             "🗑️", "roles"),
    "role_update":      ("Modifier un rôle",              "✏️", "roles"),
    "role_perm_danger": ("Perms dangereuses sur un rôle", "☢️", "roles"),
    "role_give_danger": ("Donner un rôle dangereux",      "🎖️", "roles"),
    "channel_create":   ("Créer un salon",                "📁", "salons"),
    "channel_delete":   ("Supprimer un salon",            "🗑️", "salons"),
    "channel_update":   ("Modifier un salon",             "✏️", "salons"),
    "overwrite_update": ("Modifier les perms d'un salon", "🔐", "salons"),
    "guild_update":     ("Modifier le serveur",           "🏠", "serveur"),
    "vanity_url":       ("Modifier la vanity URL",        "🔗", "serveur"),
    "webhook_create":   ("Créer un webhook",              "🪝", "serveur"),
    "webhook_delete":   ("Supprimer un webhook",          "🪝", "serveur"),
    "emoji_delete":     ("Supprimer un emoji",            "😶", "serveur"),
}
# Toujours interdites sauf Buyer (pas de limite configurable)
FORCED_ACTIONS = {
    "bot_add": ("Ajouter un bot non whitelisté",    "🤖", "bots"),
    "tamper":  ("Atteinte au bot / à la hiérarchie", "⚠️", "bots"),
}
ALL_ACTIONS = {**ACTIONS, **FORCED_ACTIONS}

ACTION_GROUPS = [
    ("👥 Membres", ["ban", "unban", "kick", "timeout", "prune", "vdisconnect", "vmove"]),
    ("🎭 Rôles",   ["role_create", "role_delete", "role_update", "role_perm_danger", "role_give_danger"]),
    ("📁 Salons",  ["channel_create", "channel_delete", "channel_update", "overwrite_update"]),
    ("🏠 Serveur", ["guild_update", "vanity_url", "webhook_create", "webhook_delete", "emoji_delete"]),
]

# {action: {rang: (max, fenêtre_minutes)}} — rang 0 (aucun) absent = interdit
DEFAULT_LIMITS = {
    "ban":              {1: (2, 30),  2: (5, 30),   3: (15, 30)},
    "unban":            {1: (5, 60),  2: (15, 60),  3: (30, 60)},
    "kick":             {1: (3, 30),  2: (10, 30),  3: (25, 30)},
    "timeout":          {1: (10, 30), 2: (25, 30),  3: (50, 30)},
    "prune":            {3: (1, 1440)},
    "vdisconnect":      {1: (10, 30), 2: (30, 30),  3: (60, 30)},
    "vmove":            {1: (15, 30), 2: (30, 30),  3: (60, 30)},
    "role_create":      {1: (1, 60),  2: (3, 60),   3: (10, 60)},
    "role_delete":      {2: (1, 60),  3: (5, 60)},
    "role_update":      {1: (2, 60),  2: (10, 60),  3: (25, 60)},
    "role_perm_danger": {3: (1, 1440)},
    "role_give_danger": {2: (3, 60),  3: (10, 60)},
    "channel_create":   {1: (2, 60),  2: (5, 60),   3: (15, 60)},
    "channel_delete":   {2: (2, 60),  3: (10, 60)},
    "channel_update":   {1: (5, 60),  2: (15, 60),  3: (40, 60)},
    "overwrite_update": {1: (5, 60),  2: (15, 60),  3: (40, 60)},
    "guild_update":     {2: (2, 1440), 3: (10, 1440)},
    "vanity_url":       {},
    "webhook_create":   {2: (2, 60),  3: (5, 60)},
    "webhook_delete":   {1: (2, 60),  2: (5, 60),   3: (15, 60)},
    "emoji_delete":     {2: (3, 60),  3: (10, 60)},
}

DANGER_PERMS = ["administrator", "ban_members", "kick_members", "manage_guild", "manage_roles",
                "manage_channels", "manage_webhooks", "mention_everyone"]
DANGER_MASK = discord.Permissions(**{p: True for p in DANGER_PERMS}).value

PUNISH_MODES = {"ban": "🔨 Ban", "kick": "👢 Kick", "derank": "📉 Derank (retrait des rôles)"}

# Salons créés par %categorie : nom -> (topic, actions routées)
LOG_GROUPS = {
    "logs-membres":   ("Ban, unban, kick, timeout, prune", ["ban", "unban", "kick", "timeout", "prune"]),
    "logs-vocal":     ("Déconnexions et déplacements forcés", ["vdisconnect", "vmove"]),
    "logs-roles":     ("Création, suppression, modification, perms dangereuses",
                       ["role_create", "role_delete", "role_update", "role_perm_danger", "role_give_danger"]),
    "logs-salons":    ("Création, suppression, modification, dérogations",
                       ["channel_create", "channel_delete", "channel_update", "overwrite_update"]),
    "logs-serveur":   ("Paramètres, vanity URL, webhooks, emojis",
                       ["guild_update", "vanity_url", "webhook_create", "webhook_delete", "emoji_delete"]),
    "logs-bots":      ("Bots ajoutés, atteintes au bot / à la hiérarchie", ["bot_add", "tamper"]),
    "logs-sanctions": ("Sanctions automatiques et reverts", ["_sanction"]),
    "logs-antifast":  ("Commandes, config, backups, erreurs", ["_internal"]),
}


# ========================= DATABASE =========================

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS ranks (user_id TEXT PRIMARY KEY, rank INTEGER NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS log_channels (guild_id TEXT PRIMARY KEY, channel_id TEXT NOT NULL)")
    c.execute("""CREATE TABLE IF NOT EXISTS log_action_channels (
        guild_id TEXT NOT NULL, action TEXT NOT NULL, channel_id TEXT NOT NULL,
        PRIMARY KEY (guild_id, action))""")
    c.execute("""CREATE TABLE IF NOT EXISTS log_category (
        guild_id TEXT PRIMARY KEY, category_id TEXT NOT NULL, set_by TEXT, ts INTEGER)""")
    c.execute("""CREATE TABLE IF NOT EXISTS action_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL, user_id TEXT NOT NULL, action TEXT NOT NULL,
        target_id TEXT, label TEXT, status TEXT, counted INTEGER DEFAULT 0, ts INTEGER NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ah_guild_ts ON action_history (guild_id, ts)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ah_user ON action_history (guild_id, user_id, ts)")
    c.execute("""CREATE TABLE IF NOT EXISTS auto_sanctions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL, user_id TEXT NOT NULL, action TEXT NOT NULL,
        reason TEXT, result TEXT, reverts INTEGER DEFAULT 0, ts INTEGER NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_id TEXT NOT NULL, ts INTEGER NOT NULL, trigger TEXT, data TEXT NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_backups_guild ON backups (guild_id, ts DESC)")
    c.execute("""CREATE TABLE IF NOT EXISTS lockdown_state (
        guild_id TEXT PRIMARY KEY, enabled_by TEXT, ts INTEGER, saved TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS wl_bots (
        guild_id TEXT NOT NULL, bot_id TEXT NOT NULL, name TEXT, added_by TEXT, ts INTEGER,
        PRIMARY KEY (guild_id, bot_id))""")
    c.execute("INSERT OR IGNORE INTO config VALUES ('prefix', ?)", (DEFAULT_PREFIX,))
    c.execute("INSERT OR REPLACE INTO config VALUES ('buyer_ids', ?)",
              (json.dumps([str(i) for i in DEFAULT_BUYER_IDS]),))
    conn.commit()
    conn.close()


def db_exec(sql, params=()):
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    rc, lid = cur.rowcount, cur.lastrowid
    conn.close()
    return rc, lid


def db_all(sql, params=()):
    conn = get_db()
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return rows


def db_one(sql, params=()):
    rows = db_all(sql, params)
    return rows[0] if rows else None


_config_cache = {}


def get_config(key):
    if key not in _config_cache:
        row = db_one("SELECT value FROM config WHERE key = ?", (key,))
        _config_cache[key] = row["value"] if row else None
    return _config_cache[key]


def set_config(key, value):
    db_exec("INSERT OR REPLACE INTO config VALUES (?, ?)", (key, str(value)))
    _config_cache[key] = str(value)
    if key == "prefix":
        _prefix_cache["value"] = str(value)


def get_prefix_cached():
    if _prefix_cache["value"] is None:
        _prefix_cache["value"] = get_config("prefix") or DEFAULT_PREFIX
    return _prefix_cache["value"]


# ---- Rangs (cache mémoire) ----
_rank_cache = {}
_buyer_cache = set()


def load_ranks():
    _rank_cache.clear()
    for r in db_all("SELECT user_id, rank FROM ranks"):
        _rank_cache[r["user_id"]] = r["rank"]
    _buyer_cache.clear()
    try:
        _buyer_cache.update(str(i) for i in json.loads(get_config("buyer_ids") or "[]"))
    except (json.JSONDecodeError, TypeError):
        pass


def get_rank_db(user_id):
    uid = str(user_id)
    if uid in _buyer_cache:
        return 4
    return _rank_cache.get(uid, 0)


def set_rank_db(user_id, rank):
    uid = str(user_id)
    if rank == 0:
        db_exec("DELETE FROM ranks WHERE user_id = ?", (uid,))
        _rank_cache.pop(uid, None)
    else:
        db_exec("INSERT OR REPLACE INTO ranks VALUES (?, ?)", (uid, rank))
        _rank_cache[uid] = rank


def get_ranks_by_level(level):
    return [uid for uid, r in _rank_cache.items() if r == level]


# ---- Limites (cache) ----
_limits_cache = {"value": None}


def get_limits():
    if _limits_cache["value"] is None:
        merged = {a: dict(v) for a, v in DEFAULT_LIMITS.items()}
        raw = get_config("limits")
        if raw:
            try:
                for action, ranks in json.loads(raw).items():
                    if action in ACTIONS:
                        merged[action] = {int(k): tuple(v) for k, v in ranks.items()}
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        _limits_cache["value"] = merged
    return _limits_cache["value"]


def _save_limits(limits):
    set_config("limits", json.dumps({a: {str(r): list(v) for r, v in rv.items()} for a, rv in limits.items()}))
    _limits_cache["value"] = None


def get_limit_for(action, rank):
    """(max, minutes). Buyer -> None (illimité). Pas d'entrée -> (0, 0) = interdit."""
    if rank >= 4:
        return None
    return tuple(get_limits().get(action, {}).get(int(rank), (0, 0)))


def set_limit(action, rank, max_actions, window):
    limits = {a: dict(v) for a, v in get_limits().items()}
    limits.setdefault(action, {})[int(rank)] = (int(max_actions), int(window))
    _save_limits(limits)


def reset_limits(action=None):
    limits = {a: dict(v) for a, v in get_limits().items()}
    if action:
        limits[action] = dict(DEFAULT_LIMITS.get(action, {}))
    else:
        limits = {a: dict(v) for a, v in DEFAULT_LIMITS.items()}
    _save_limits(limits)


def fmt_limit(lim):
    if lim is None:
        return "illimité"
    m, w = lim
    return "✖ interdit" if m <= 0 else f"**{m}** / {w} min"


def get_disabled_actions():
    try:
        return set(json.loads(get_config("disabled_actions") or "[]"))
    except (json.JSONDecodeError, TypeError):
        return set()


def toggle_action(action):
    d = get_disabled_actions()
    d.symmetric_difference_update({action})
    set_config("disabled_actions", json.dumps(sorted(d)))
    return action not in d


def get_punish_mode():
    m = get_config("punish") or "ban"
    return m if m in PUNISH_MODES else "ban"


# ---- Bots whitelistés (cache par serveur) ----
_wlbots_cache = {}


def wl_bots(gid):
    gid = str(gid)
    if gid not in _wlbots_cache:
        _wlbots_cache[gid] = {int(r["bot_id"]) for r in db_all("SELECT bot_id FROM wl_bots WHERE guild_id = ?", (gid,))}
    return _wlbots_cache[gid]


def wl_bot_add(gid, bot_id, name, added_by):
    db_exec("INSERT OR REPLACE INTO wl_bots VALUES (?, ?, ?, ?, ?)",
            (str(gid), str(bot_id), name, str(added_by), int(time.time())))
    wl_bots(gid).add(int(bot_id))


def wl_bot_remove(gid, bot_id):
    rc, _ = db_exec("DELETE FROM wl_bots WHERE guild_id = ? AND bot_id = ?", (str(gid), str(bot_id)))
    wl_bots(gid).discard(int(bot_id))
    return rc > 0


# ---- Logs (cache) ----
_logch_cache = {}


def get_log_channel(gid):
    key = ("global", str(gid))
    if key not in _logch_cache:
        row = db_one("SELECT channel_id FROM log_channels WHERE guild_id = ?", (str(gid),))
        _logch_cache[key] = row["channel_id"] if row else None
    return _logch_cache[key]


def set_log_channel(gid, cid):
    db_exec("INSERT OR REPLACE INTO log_channels VALUES (?, ?)", (str(gid), str(cid)))
    _logch_cache[("global", str(gid))] = str(cid)


def get_action_channels(gid):
    key = ("actions", str(gid))
    if key not in _logch_cache:
        _logch_cache[key] = {r["action"]: r["channel_id"] for r in
                             db_all("SELECT action, channel_id FROM log_action_channels WHERE guild_id = ?", (str(gid),))}
    return _logch_cache[key]


def set_action_channel(gid, action, cid):
    db_exec("INSERT OR REPLACE INTO log_action_channels VALUES (?, ?, ?)", (str(gid), action, str(cid)))
    get_action_channels(gid)[action] = str(cid)


def clear_action_channels(gid):
    db_exec("DELETE FROM log_action_channels WHERE guild_id = ?", (str(gid),))
    _logch_cache.pop(("actions", str(gid)), None)


# ---- Historique ----

def record_action(gid, uid, action, target_id=None, label=None, status="ok", counted=0):
    try:
        db_exec("INSERT INTO action_history (guild_id, user_id, action, target_id, label, status, counted, ts) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (str(gid), str(uid), action, str(target_id) if target_id else None,
                 (label or "")[:200], status, counted, int(time.time())))
    except sqlite3.Error as e:
        log.warning(f"record_action: {e}")


def record_sanction(gid, uid, action, reason, result, reverts):
    _, lid = db_exec("INSERT INTO auto_sanctions (guild_id, user_id, action, reason, result, reverts, ts) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (str(gid), str(uid), action, reason[:500], result[:300], reverts, int(time.time())))
    return lid


# ---- Emojis personnalisables ----
DEFAULT_EMOJIS = {
    "help_home_title":     "🛡️",
    "help_cat_protection": "⏱️",
    "help_cat_rangs":      "👥",
    "help_cat_backups":    "📦",
    "help_cat_urgence":    "🚨",
    "help_cat_suivi":      "📜",
    "help_cat_system":     "🛠️",
    "panel_title":         "🛡️",
    "status_on":           "🟢",
    "status_off":          "🔴",
}
EMOJI_LABELS = {
    "help_home_title":     "Help · Titre accueil",
    "help_cat_protection": "Help · Catégorie Protection",
    "help_cat_rangs":      "Help · Catégorie Rangs & bots",
    "help_cat_backups":    "Help · Catégorie Backups",
    "help_cat_urgence":    "Help · Catégorie Urgence",
    "help_cat_suivi":      "Help · Catégorie Suivi",
    "help_cat_system":     "Help · Catégorie Système",
    "panel_title":         "Panneau · Titre",
    "status_on":           "Panneau · Surveillance active",
    "status_off":          "Panneau · Surveillance coupée",
}


def get_emojis():
    data = {}
    try:
        data = json.loads(get_config("emojis") or "{}")
    except (json.JSONDecodeError, TypeError):
        pass
    merged = dict(DEFAULT_EMOJIS)
    merged.update({k: v for k, v in data.items() if k in DEFAULT_EMOJIS})
    return merged


def get_emoji(key):
    return get_emojis().get(key, DEFAULT_EMOJIS.get(key, ""))


def set_emoji(key, value):
    e = get_emojis()
    e[key] = value
    set_config("emojis", json.dumps(e))


def reset_emojis():
    set_config("emojis", json.dumps(DEFAULT_EMOJIS))


# ========================= HELPERS =========================

def rank_name(level):
    return {4: "Buyer", 3: "Sys", 2: "Owner", 1: "Whitelist", 0: "Aucun"}.get(level, "Aucun")


def has_min_rank(user_id, minimum):
    return get_rank_db(user_id) >= minimum


def embed_color():
    return 0x2b2d31


def success_embed(title, desc=""):
    return discord.Embed(title=title, description=desc, color=0x43b581)


def error_embed(title, desc=""):
    return discord.Embed(title=title, description=desc, color=0xf04747)


def warn_embed(title, desc=""):
    return discord.Embed(title=title, description=desc, color=0xfaa61a)


def info_embed(title, desc=""):
    return discord.Embed(title=title, description=desc, color=embed_color())


def denied(min_rank):
    if min_rank >= 4:
        return error_embed("❌ Permission refusée", "Seul le **Buyer** peut utiliser cette commande.")
    return error_embed("❌ Permission refusée", f"**{rank_name(min_rank)}+** requis.")


async def gate(ctx, min_rank):
    """Rang 0 : refus silencieux (🔒). Rang insuffisant : embed d'erreur."""
    r = get_rank_db(ctx.author.id)
    if r >= min_rank:
        return True
    if r == 0:
        try:
            await ctx.message.add_reaction("🔒")
        except discord.HTTPException:
            pass
    else:
        await ctx.send(embed=denied(min_rank))
    return False


def _emoji_for_select(raw):
    if not raw:
        return None
    try:
        return discord.PartialEmoji.from_str(raw)
    except Exception:
        return None


def apply_thumbnail(em, guild):
    if guild and getattr(guild, "icon", None):
        try:
            em.set_thumbnail(url=guild.icon.url)
        except (AttributeError, TypeError):
            pass


def now_ts():
    return int(time.time())


def danger_names(value):
    p = discord.Permissions(value)
    return [n for n in DANGER_PERMS if getattr(p, n)]


def can_manage(guild, member):
    if not isinstance(member, discord.Member) or member.id == guild.owner_id:
        return False
    return guild.me.top_role > member.top_role


def is_bot_role(guild, role):
    tags = getattr(role, "tags", None)
    return bool(tags and getattr(tags, "bot_id", None) == guild.me.id)


async def resolve_user_or_id(ctx, user_input):
    if not user_input:
        return None, None
    raw = user_input.strip()
    try:
        user_id = int(raw.strip("<@!>"))
    except ValueError:
        try:
            m = await commands.MemberConverter().convert(ctx, raw)
            return m, m.id
        except commands.CommandError:
            pass
        try:
            u = await commands.UserConverter().convert(ctx, raw)
            return u, u.id
        except commands.CommandError:
            return None, None
    if ctx.guild:
        member = ctx.guild.get_member(user_id)
        if member:
            return member, user_id
    try:
        return await bot.fetch_user(user_id), user_id
    except discord.HTTPException:
        return None, user_id


def format_user_display(display_obj, user_id):
    if display_obj is not None:
        return f"{display_obj.mention} ({display_obj.id})"
    return f"<@{user_id}> ({user_id}) *(hors serveur)*"


# ========================= BOT SETUP =========================

init_db()
load_ranks()

intents = discord.Intents.all()


def get_prefix(bot, message):
    return get_prefix_cached()


bot = commands.Bot(command_prefix=get_prefix, intents=intents, help_command=None)


@bot.check
async def _guild_only(ctx):
    return ctx.guild is not None


# ========================= LOGS =========================

def _resolve_log_channel(guild, action=None):
    if action:
        cid = get_action_channels(guild.id).get(action)
        if cid:
            ch = guild.get_channel(int(cid))
            if ch:
                return ch
    cid = get_log_channel(guild.id)
    return guild.get_channel(int(cid)) if cid else None


async def send_log_embed(guild, em, action=None, content=None):
    ch = _resolve_log_channel(guild, action)
    if not ch:
        return
    try:
        await ch.send(content=content, embed=em,
                      allowed_mentions=discord.AllowedMentions(users=True, roles=False, everyone=False))
    except discord.HTTPException as e:
        log.warning(f"send_log: {e}")


def fire_log(guild, em, action=None, content=None):
    """Log non bloquant (n'attend pas Discord : la protection reste instantanée)."""
    asyncio.create_task(send_log_embed(guild, em, action=action, content=content))


async def internal_log(guild, title, author=None, desc="", color=0x3498db):
    em = discord.Embed(title=f"⚙️ {title}", description=desc, color=color, timestamp=datetime.now(timezone.utc))
    if author:
        em.add_field(name="Par", value=f"{author.mention} ({author.id})", inline=False)
    await send_log_embed(guild, em, action="_internal")


async def send_log(guild, action, author, target_display, target_id, color=0xf04747):
    em = discord.Embed(title=f"📋 {action}", color=color, timestamp=datetime.now(timezone.utc))
    em.add_field(name="Modérateur", value=f"{author.mention} ({author.id})", inline=True)
    em.add_field(name="Utilisateur", value=format_user_display(target_display, target_id), inline=True)
    await send_log_embed(guild, em, action="_internal")


# ========================= SNAPSHOTS =========================

def snapshot_overwrites(ch):
    out = {}
    for target, ow in ch.overwrites.items():
        allow, deny = ow.pair()
        out[str(target.id)] = {"type": "role" if isinstance(target, discord.Role) else "member",
                               "allow": allow.value, "deny": deny.value}
    return out


def snapshot_channel(ch):
    data = {
        "id": str(ch.id), "name": ch.name, "type": ch.type.name, "position": ch.position,
        "category_id": str(ch.category_id) if getattr(ch, "category_id", None) else None,
        "topic": getattr(ch, "topic", None), "nsfw": getattr(ch, "nsfw", False),
        "slowmode_delay": getattr(ch, "slowmode_delay", 0) or 0,
        "bitrate": getattr(ch, "bitrate", None), "user_limit": getattr(ch, "user_limit", None),
        "overwrites": snapshot_overwrites(ch),
    }
    if isinstance(ch, discord.CategoryChannel):
        data["children"] = [str(c.id) for c in ch.guild.channels if getattr(c, "category_id", None) == ch.id]
    return data


def snapshot_role(role):
    return {
        "id": str(role.id), "name": role.name, "permissions": role.permissions.value,
        "color": role.color.value, "hoist": role.hoist, "mentionable": role.mentionable,
        "position": role.position, "default": role.is_default(), "managed": role.managed,
    }


async def build_backup_data(guild):
    roles = [snapshot_role(r) for r in sorted(guild.roles, key=lambda r: r.position)]
    channels = [snapshot_channel(c) for c in sorted(guild.channels, key=lambda c: (c.type.name != "category", c.position))]
    members = {}
    for m in guild.members:
        if m.bot:
            continue
        rids = [str(r.id) for r in m.roles if not r.is_default() and not r.managed]
        if rids:
            members[str(m.id)] = rids
    icon_b64 = None
    if guild.icon:
        try:
            icon_b64 = base64.b64encode(await guild.icon.read()).decode()
        except discord.HTTPException:
            pass
    gdata = {"name": guild.name, "icon_b64": icon_b64, "vanity": guild.vanity_url_code,
             "verification_level": guild.verification_level.value,
             "explicit_content_filter": guild.explicit_content_filter.value,
             "default_notifications": guild.default_notifications.value}
    return {"roles": roles, "channels": channels, "members": members, "guild": gdata}


_latest_backup = {}  # gid -> data (en mémoire, pour les reverts instantanés)


async def do_backup(guild, trigger="auto"):
    try:
        data = await build_backup_data(guild)
        _, bid = db_exec("INSERT INTO backups (guild_id, ts, trigger, data) VALUES (?, ?, ?, ?)",
                         (str(guild.id), now_ts(), trigger, json.dumps(data)))
        db_exec("DELETE FROM backups WHERE id IN (SELECT id FROM backups WHERE guild_id = ? "
                "ORDER BY ts DESC LIMIT -1 OFFSET ?)", (str(guild.id), MAX_BACKUPS_PER_GUILD))
        _latest_backup[guild.id] = data
        return bid, None
    except Exception as e:
        log.error(f"Backup {guild.name} : {e}\n{traceback.format_exc()}")
        return None, f"{type(e).__name__}: {e}"


def latest_backup(gid):
    if gid in _latest_backup:
        return _latest_backup[gid]
    row = db_one("SELECT data FROM backups WHERE guild_id = ? ORDER BY ts DESC LIMIT 1", (str(gid),))
    if row:
        _latest_backup[gid] = json.loads(row["data"])
        return _latest_backup[gid]
    return None


# Snapshots des éléments supprimés (capturés à l'instant de la suppression)
_deleted_channels = {}  # id -> (ts, snapshot)
_deleted_roles = {}     # id -> (ts, snapshot, member_ids)
_deleted_emojis = {}    # id -> (ts, Emoji)


async def wait_snapshot(store, key, timeout=2.0):
    end = time.time() + timeout
    while time.time() < end:
        if key in store:
            return store[key]
        await asyncio.sleep(0.05)
    return store.get(key)


# ========================= REVERTS =========================

def build_overwrites(guild, ows, id_map=None):
    id_map = id_map or {}
    result = {}
    for tid, ow in (ows or {}).items():
        target = id_map.get(tid)
        if target is None:
            target = guild.get_role(int(tid)) if ow["type"] == "role" else guild.get_member(int(tid))
        if target is None:
            continue
        result[target] = discord.PermissionOverwrite.from_pair(discord.Permissions(int(ow["allow"])),
                                                               discord.Permissions(int(ow["deny"])))
    return result


async def recreate_channel(guild, snap, id_map=None, reason="Antifast : revert suppression de salon"):
    id_map = id_map or {}
    ows = build_overwrites(guild, snap.get("overwrites"), id_map)
    cat = None
    if snap.get("category_id"):
        cat = id_map.get(snap["category_id"]) or guild.get_channel(int(snap["category_id"]))
        if not isinstance(cat, discord.CategoryChannel):
            cat = None
    kind = snap.get("type", "text")
    common = {"name": snap["name"], "overwrites": ows, "reason": reason, "position": snap.get("position")}
    if kind == "category":
        new = await guild.create_category(**common)
        for cid in snap.get("children", []):
            child = guild.get_channel(int(cid))
            if child and getattr(child, "category_id", None) is None:
                try:
                    await child.edit(category=new, sync_permissions=False, reason=reason)
                except discord.HTTPException:
                    pass
        return new
    if kind in ("text", "news"):
        return await guild.create_text_channel(category=cat, topic=snap.get("topic"), nsfw=snap.get("nsfw", False),
                                               slowmode_delay=snap.get("slowmode_delay") or 0,
                                               news=(kind == "news"), **common)
    if kind == "voice":
        return await guild.create_voice_channel(category=cat, bitrate=min(snap.get("bitrate") or 64000, int(guild.bitrate_limit)),
                                                user_limit=snap.get("user_limit") or 0, **common)
    if kind == "stage_voice":
        return await guild.create_stage_channel(category=cat, **common)
    if kind in ("forum", "media") and hasattr(guild, "create_forum"):
        return await guild.create_forum(category=cat, topic=snap.get("topic"), **common)
    return await guild.create_text_channel(category=cat, **common)


async def recreate_role(guild, snap, members=None, reason="Antifast : revert suppression de rôle"):
    role = await guild.create_role(
        name=snap["name"], permissions=discord.Permissions(int(snap["permissions"])),
        colour=discord.Colour(int(snap["color"])), hoist=snap["hoist"], mentionable=snap["mentionable"], reason=reason)
    try:
        pos = min(int(snap.get("position", 1)), guild.me.top_role.position - 1)
        if pos > 0:
            await role.edit(position=pos, reason=reason)
    except discord.HTTPException:
        pass
    given = 0
    for mid in list(members or [])[:MAX_ROLE_REASSIGN]:
        m = guild.get_member(int(mid))
        if m:
            try:
                await m.add_roles(role, reason=reason)
                given += 1
            except discord.HTTPException:
                pass
    return role, given


def role_members_from_backup(gid, role_id):
    bk = latest_backup(gid)
    if not bk:
        return []
    return [uid for uid, rids in bk.get("members", {}).items() if str(role_id) in rids]


async def rv_unban(guild, uid):
    await guild.unban(discord.Object(id=uid), reason="Antifast : revert ban abusif")
    return "débanni"


async def rv_reban(guild, uid):
    await guild.ban(discord.Object(id=uid), reason="Antifast : revert unban abusif", delete_message_seconds=0)
    return "rebanni"


async def rv_untimeout(guild, uid):
    m = guild.get_member(uid)
    if not m:
        return None
    await m.timeout(None, reason="Antifast : revert timeout abusif")
    return "timeout retiré"


async def rv_member_roles(guild, uid, add_ids=(), remove_ids=()):
    m = guild.get_member(uid)
    if not m:
        return None
    to_add = [r for r in (guild.get_role(i) for i in add_ids) if r and r < guild.me.top_role and r not in m.roles]
    to_rm = [r for r in (guild.get_role(i) for i in remove_ids) if r and r < guild.me.top_role and r in m.roles]
    if to_add:
        await m.add_roles(*to_add, reason="Antifast : revert rôles")
    if to_rm:
        await m.remove_roles(*to_rm, reason="Antifast : revert rôles")
    return f"rôles restaurés ({len(to_add)}+ / {len(to_rm)}-)"


async def rv_delete_role(guild, rid):
    r = guild.get_role(rid)
    if r:
        await r.delete(reason="Antifast : revert création de rôle")
    return "rôle supprimé"


async def rv_delete_channel(guild, cid):
    c = guild.get_channel(cid)
    if c:
        await c.delete(reason="Antifast : revert création de salon")
    return "salon supprimé"


async def rv_recreate_channel(guild, snap):
    new = await recreate_channel(guild, snap)
    return f"salon recréé {new.mention}"


async def rv_recreate_role(guild, snap, members):
    role, given = await recreate_role(guild, snap, members)
    return f"rôle recréé {role.mention} (redonné à {given} membre(s))"


async def rv_edit_role(guild, rid, kwargs):
    r = guild.get_role(rid)
    if not r or not kwargs:
        return None
    await r.edit(reason="Antifast : revert modification de rôle", **kwargs)
    return "rôle restauré"


async def rv_edit_channel(guild, cid, kwargs):
    c = guild.get_channel(cid)
    if not c or not kwargs:
        return None
    await c.edit(reason="Antifast : revert modification de salon", **kwargs)
    return "salon restauré"


async def rv_overwrite(guild, cid, target_id, allow, deny):
    c = guild.get_channel(cid)
    target = guild.get_role(target_id) or guild.get_member(target_id)
    if not c or not target:
        return None
    ow = None if allow is None else discord.PermissionOverwrite.from_pair(discord.Permissions(allow), discord.Permissions(deny))
    await c.set_permissions(target, overwrite=ow, reason="Antifast : revert permissions de salon")
    return "permissions restaurées"


async def rv_edit_guild(guild, kwargs):
    if not kwargs:
        return None
    await guild.edit(reason="Antifast : revert modification du serveur", **kwargs)
    return "serveur restauré"


async def rv_delete_webhook(guild, wid):
    try:
        wh = await bot.fetch_webhook(wid)
        await wh.delete(reason="Antifast : revert création de webhook")
    except discord.NotFound:
        pass
    return "webhook supprimé"


async def rv_recreate_emoji(guild, emoji):
    data = await emoji.read()
    new = await guild.create_custom_emoji(name=emoji.name, image=data, reason="Antifast : revert suppression d'emoji")
    return f"emoji recréé {new}"


async def rv_ban_bot(guild, bot_id):
    await guild.ban(discord.Object(id=bot_id), reason="Antifast : bot non whitelisté", delete_message_seconds=0)
    return "bot banni"


_vanity_set_by_us = {}  # gid -> code qu'on vient de remettre (pour ignorer notre propre event)


async def set_vanity(guild, code, reason):
    _vanity_set_by_us[guild.id] = code
    await guild.edit(vanity_code=code, reason=reason)


async def rv_vanity(guild, code):
    if not code:
        return None
    if guild.vanity_url_code == code:
        return "vanity déjà restaurée"
    await set_vanity(guild, code, "Antifast : revert vanity URL")
    return f"vanity restaurée ({code})"


# ========================= MOTEUR DE PROTECTION =========================

_quota = defaultdict(deque)      # (gid, uid, action) -> deque[ts]
_recent = defaultdict(deque)     # (gid, uid) -> deque[(ts, action, label, revert)]
_punished = {}                   # (gid, uid) -> ts
_bot_add_seen = set()            # (gid, bot_id)


def _prune_ts(dq, now, window):
    while dq and now - dq[0] > window:
        dq.popleft()


def hierarchy_violation(actor_id, target_id):
    if target_id is None:
        return None
    if bot.user and target_id == bot.user.id:
        return "Action contre le bot Antifast"
    ar, tr = get_rank_db(actor_id), get_rank_db(target_id)
    if tr >= 1 and tr >= ar and ar < 4:
        return f"Action contre un **{rank_name(tr)}** (rang supérieur ou égal au sien)"
    return None


async def handle_action(guild, actor_id, action, target_id=None, label=None, revert=None, forced=None):
    """Cœur du bot. Retourne True si l'action est autorisée, False si sanctionnée."""
    if actor_id is None or (bot.user and actor_id == bot.user.id):
        return True
    if action in ACTIONS and action in get_disabled_actions() and not forced:
        return True
    gid = guild.id
    now = time.time()
    meta = ALL_ACTIONS.get(action, (action, "📋", ""))

    if actor_id in wl_bots(gid):
        record_action(gid, actor_id, action, target_id, label, "bot")
        fire_log(guild, _action_embed(meta, actor_id, label, "🤖 Bot whitelisté", 0x95a5a6), action)
        return True

    rank = get_rank_db(actor_id)
    if rank >= 4 or actor_id == guild.owner_id:
        record_action(gid, actor_id, action, target_id, label, "buyer")
        txt = "👑 Buyer (illimité)" if rank >= 4 else "👑 Propriétaire du serveur"
        fire_log(guild, _action_embed(meta, actor_id, label, txt, 0x9b59b6), action)
        return True

    reason = forced
    if not reason:
        m, w = get_limit_for(action, rank)
        dq = _quota[(gid, actor_id, action)]
        _prune_ts(dq, now, w * 60)
        if m <= 0:
            reason = f"Action interdite pour le rang **{rank_name(rank)}**"
        elif len(dq) >= m:
            reason = f"Limite dépassée : **{len(dq) + 1}** actions en moins de **{w} min** (max **{m}**)"
        else:
            dq.append(now)
            if revert:
                _recent[(gid, actor_id)].append((now, action, label, revert))
            record_action(gid, actor_id, action, target_id, label, "ok", counted=1)
            used, remaining = len(dq), m - len(dq)
            bar = "🟢" if remaining > m * 0.5 else ("🟡" if remaining > 0 else "🔴")
            em = _action_embed(meta, actor_id, label, rank_name(rank),
                               0x43b581 if remaining > m * 0.3 else (0xf1c40f if remaining > 0 else 0xe67e22))
            em.add_field(name="📊 Quota",
                         value=f"{bar} **{used}/{m}** sur **{w} min** — il reste **{remaining}** action(s).",
                         inline=False)
            fire_log(guild, em, action, content=f"<@{actor_id}>")
            return True

    record_action(gid, actor_id, action, target_id, label, "violation")
    await on_violation(guild, actor_id, action, label, reason, revert, rank)
    return False


def _action_embed(meta, actor_id, label, rank_txt, color):
    em = discord.Embed(title=f"{meta[1]} {meta[0]}", color=color, timestamp=datetime.now(timezone.utc))
    em.add_field(name="Auteur", value=f"<@{actor_id}>", inline=True)
    em.add_field(name="Rang", value=rank_txt, inline=True)
    if label:
        em.add_field(name="Cible", value=str(label)[:1024], inline=False)
    return em


async def on_violation(guild, actor_id, action, label, reason, revert, rank):
    gid = guild.id
    now = time.time()
    key = (gid, actor_id)

    reverts = []
    if revert:
        reverts.append((action, label, revert))
    for ts, a, lbl, fn in reversed(_recent.pop(key, deque())):
        if now - ts <= RECENT_REVERT_WINDOW:
            reverts.append((a, lbl, fn))

    first = now - _punished.get(key, 0) > PUNISH_COOLDOWN
    punish_task = None
    if first:
        _punished[key] = now
        punish_task = asyncio.create_task(punish_actor(guild, actor_id, reason, action))

    results = []
    for a, lbl, fn in reverts:
        try:
            res = await fn()
            results.append(f"✅ `{a}` — {res or 'ok'}")
        except discord.HTTPException as e:
            results.append(f"❌ `{a}` — {type(e).__name__}")
        except Exception as e:
            log.error(f"revert {a}: {e}\n{traceback.format_exc()}")
            results.append(f"❌ `{a}` — erreur")

    result_txt = await punish_task if punish_task else "*déjà sanctionné*"
    if first:
        record_sanction(gid, actor_id, action, reason, result_txt, len(results))

    meta = ALL_ACTIONS.get(action, (action, "📋", ""))
    em = discord.Embed(title="🚨 SANCTION AUTOMATIQUE" if first else "🚨 Action bloquée",
                       color=0xf04747, timestamp=datetime.now(timezone.utc))
    em.add_field(name="Auteur", value=f"<@{actor_id}> ({actor_id})", inline=True)
    em.add_field(name="Rang", value=rank_name(rank), inline=True)
    em.add_field(name="Action", value=f"{meta[1]} {meta[0]}", inline=True)
    if label:
        em.add_field(name="Cible", value=str(label)[:1024], inline=False)
    em.add_field(name="Motif", value=reason[:1024], inline=False)
    em.add_field(name="Sanction", value=result_txt[:1024], inline=False)
    if results:
        txt = "\n".join(results[:12]) + (f"\n*+{len(results) - 12} autres*" if len(results) > 12 else "")
        em.add_field(name=f"↩️ Reverts ({len(results)})", value=txt[:1024], inline=False)

    ping = f"<@{actor_id}>"
    if first:
        ping += " " + " ".join(f"<@{b}>" for b in _buyer_cache)
    await send_log_embed(guild, em, action=action, content=ping)
    if get_action_channels(gid).get("_sanction") and get_action_channels(gid).get("_sanction") != get_action_channels(gid).get(action):
        await send_log_embed(guild, em, action="_sanction")


async def derank(guild, member):
    if not isinstance(member, discord.Member):
        return "membre introuvable"
    removable = [r for r in member.roles if not r.is_default() and not r.managed and r < guild.me.top_role]
    out = []
    if removable:
        try:
            await member.remove_roles(*removable, reason="Antifast : derank")
            out.append(f"{len(removable)} rôle(s) retiré(s)")
        except discord.HTTPException:
            out.append("retrait des rôles échoué")
    above = [r for r in member.roles if r >= guild.me.top_role and not r.is_default()]
    if above:
        out.append(f"⚠️ {len(above)} rôle(s) au-dessus du bot — monte le rôle du bot !")
    return ", ".join(out) or "aucun rôle à retirer"


async def punish_actor(guild, actor_id, reason, action):
    mode = get_punish_mode()
    member = guild.get_member(actor_id)

    async def _dm():
        if member is None or member.bot:
            return
        try:
            await member.send(embed=error_embed(
                f"⛔ Sanction automatique — {guild.name}",
                f"**Action :** `{action}`\n**Motif :** {reason}\n\n*Contacte un Buyer si c'est une erreur.*"))
        except discord.HTTPException:
            pass

    asyncio.create_task(_dm())
    try:
        if mode == "ban":
            await guild.ban(discord.Object(id=actor_id), reason=f"Antifast : {action}", delete_message_seconds=0)
            return "🔨 **Banni**"
        if mode == "kick" and member:
            await member.kick(reason=f"Antifast : {action}")
            return "👢 **Expulsé**"
        return f"📉 **Derank** : {await derank(guild, member)}"
    except discord.Forbidden:
        return f"❌ {PUNISH_MODES[mode]} impossible (rôle trop haut) → derank : {await derank(guild, member)}"
    except discord.HTTPException as e:
        return f"❌ Échec API ({e.status}) → derank : {await derank(guild, member)}"


# ========================= AUDIT LOG (temps réel) =========================

A = discord.AuditLogAction


def _diff(entry, side, attr, default=None):
    return getattr(getattr(entry.changes, side), attr, default)


async def h_ban(e, g, actor, tid):
    await handle_action(g, actor, "ban", tid, f"<@{tid}> ({tid})", lambda: rv_unban(g, tid), hierarchy_violation(actor, tid))


async def h_unban(e, g, actor, tid):
    await handle_action(g, actor, "unban", tid, f"<@{tid}> ({tid})", lambda: rv_reban(g, tid))


async def h_kick(e, g, actor, tid):
    await handle_action(g, actor, "kick", tid, f"<@{tid}> ({tid})", None, hierarchy_violation(actor, tid))


async def h_prune(e, g, actor, tid):
    n = getattr(e.extra, "members_removed", "?")
    await handle_action(g, actor, "prune", None, f"{n} membre(s) expulsé(s)")


async def h_member_update(e, g, actor, tid):
    if _diff(e, "after", "timed_out_until"):
        await handle_action(g, actor, "timeout", tid, f"<@{tid}>", lambda: rv_untimeout(g, tid),
                            hierarchy_violation(actor, tid))


async def h_member_role_update(e, g, actor, tid):
    added = [r.id for r in (_diff(e, "after", "roles") or [])]
    removed = [r.id for r in (_diff(e, "before", "roles") or [])]

    if removed:
        forced = hierarchy_violation(actor, tid)
        if forced:
            await handle_action(g, actor, "tamper", tid, f"<@{tid}> — rôles retirés : {len(removed)}",
                                lambda: rv_member_roles(g, tid, add_ids=removed), forced)
            return

    danger = [rid for rid in added if (r := g.get_role(rid)) and r.permissions.value & DANGER_MASK]
    if danger:
        names = ", ".join(f"<@&{rid}>" for rid in danger)
        perms = sorted({p for rid in danger for p in danger_names(g.get_role(rid).permissions.value)})
        await handle_action(g, actor, "role_give_danger", tid,
                            f"<@{tid}> reçoit {names}\n*Perms : {', '.join(perms)}*",
                            lambda: rv_member_roles(g, tid, remove_ids=danger))


async def h_bot_add(e, g, actor, tid):
    _bot_add_seen.add((g.id, tid))
    if tid in wl_bots(g.id):
        record_action(g.id, actor, "bot_add", tid, f"Bot <@{tid}> (whitelisté)", "ok")
        fire_log(g, _action_embed(FORCED_ACTIONS["bot_add"], actor, f"<@{tid}> — bot whitelisté", rank_name(get_rank_db(actor)), 0x43b581), "bot_add")
        return
    if get_rank_db(actor) >= 4:
        em = info_embed("🤖 Bot ajouté par un Buyer",
                        f"**Bot :** <@{tid}>\n**Par :** <@{actor}>\n\n"
                        f"⚠️ Pense à `{get_prefix_cached()}bot <@{tid}>` sinon ses actions seront sanctionnées.")
        fire_log(g, em, "bot_add")
        record_action(g.id, actor, "bot_add", tid, f"Bot <@{tid}>", "buyer")
        return
    await handle_action(g, actor, "bot_add", tid, f"Bot <@{tid}> ({tid})", lambda: rv_ban_bot(g, tid),
                        "Seul un **Buyer** peut ajouter un bot non whitelisté")


async def h_role_create(e, g, actor, tid):
    r = g.get_role(tid)
    if r and r.managed:
        return
    await handle_action(g, actor, "role_create", tid, f"{r.name if r else tid}", lambda: rv_delete_role(g, tid))


async def h_role_delete(e, g, actor, tid):
    snap = await wait_snapshot(_deleted_roles, tid)
    if snap:
        _ts, data, members = snap
    else:
        bk = latest_backup(g.id) or {}
        data = next((r for r in bk.get("roles", []) if r["id"] == str(tid)), None)
        members = []
    if data:
        members = list(dict.fromkeys(list(members) + role_members_from_backup(g.id, tid)))
        revert = (lambda: rv_recreate_role(g, data, members)) if not data.get("managed") else None
    else:
        revert = None
    name = data["name"] if data else (_diff(e, "before", "name") or tid)
    await handle_action(g, actor, "role_delete", tid, f"@{name}", revert)


ROLE_EDIT_ATTRS = {"name": "name", "permissions": "permissions", "colour": "colour", "color": "colour",
                   "hoist": "hoist", "mentionable": "mentionable"}


async def h_role_update(e, g, actor, tid):
    role = g.get_role(tid)
    kwargs = {}
    for attr, kw in ROLE_EDIT_ATTRS.items():
        val = _diff(e, "before", attr)
        if val is not None and kw not in kwargs:
            kwargs[kw] = val
    if not kwargs:
        return
    revert = lambda: rv_edit_role(g, tid, kwargs)
    name = role.name if role else tid

    before_p = _diff(e, "before", "permissions")
    after_p = _diff(e, "after", "permissions")
    if role and (is_bot_role(g, role) or role == g.me.top_role) and before_p and after_p and after_p.value < before_p.value:
        await handle_action(g, actor, "tamper", tid, f"Rôle du bot {role.mention} modifié", revert,
                            "Retrait de permissions sur le rôle du bot")
        return
    if before_p is not None and after_p is not None:
        gained = after_p.value & DANGER_MASK & ~before_p.value
        if gained:
            await handle_action(g, actor, "role_perm_danger", tid,
                                f"<@&{tid}> reçoit : {', '.join(danger_names(gained))}", revert)
            return
    await handle_action(g, actor, "role_update", tid, f"<@&{tid}> ({name}) — {', '.join(kwargs)}", revert)


async def h_channel_create(e, g, actor, tid):
    ch = g.get_channel(tid)
    await handle_action(g, actor, "channel_create", tid, f"#{ch.name if ch else tid}", lambda: rv_delete_channel(g, tid))


async def h_channel_delete(e, g, actor, tid):
    snap = await wait_snapshot(_deleted_channels, tid)
    data = snap[1] if snap else None
    if not data:
        bk = latest_backup(g.id) or {}
        data = next((c for c in bk.get("channels", []) if c["id"] == str(tid)), None)
    name = data["name"] if data else (_diff(e, "before", "name") or tid)
    await handle_action(g, actor, "channel_delete", tid, f"#{name}", (lambda: rv_recreate_channel(g, data)) if data else None)


CHANNEL_EDIT_ATTRS = ("name", "topic", "nsfw", "slowmode_delay", "bitrate", "user_limit", "position")


async def h_channel_update(e, g, actor, tid):
    kwargs = {}
    for attr in CHANNEL_EDIT_ATTRS:
        val = _diff(e, "before", attr)
        if val is not None:
            kwargs[attr] = val
    if not kwargs:
        return
    ch = g.get_channel(tid)
    await handle_action(g, actor, "channel_update", tid,
                        f"{ch.mention if ch else tid} — {', '.join(kwargs)}", lambda: rv_edit_channel(g, tid, kwargs))


async def h_overwrite(e, g, actor, tid):
    target = e.extra
    target_id = getattr(target, "id", None)
    if target_id is None:
        return
    if e.action == A.overwrite_create:
        allow, deny = None, None
    else:
        ba, bd = _diff(e, "before", "allow"), _diff(e, "before", "deny")
        allow = ba.value if ba is not None else 0
        deny = bd.value if bd is not None else 0
        if e.action == A.overwrite_update:
            cur = None
            ch = g.get_channel(tid)
            if ch:
                cur_target = g.get_role(target_id) or g.get_member(target_id)
                cur = ch.overwrites_for(cur_target).pair() if cur_target else None
            if cur:
                if ba is None:
                    allow = cur[0].value
                if bd is None:
                    deny = cur[1].value
    ch = g.get_channel(tid)
    await handle_action(g, actor, "overwrite_update", tid,
                        f"{ch.mention if ch else tid} — perms de <@&{target_id}>" if isinstance(target, discord.Role)
                        else f"{ch.mention if ch else tid} — perms de <@{target_id}>",
                        lambda: rv_overwrite(g, tid, target_id, allow, deny))


GUILD_EDIT_ATTRS = ("name", "verification_level", "explicit_content_filter", "default_notifications",
                    "afk_timeout", "afk_channel", "system_channel", "description")


async def h_guild_update(e, g, actor, tid):
    before = e.changes.before
    if hasattr(before, "vanity_url_code") or hasattr(e.changes.after, "vanity_url_code"):
        old = getattr(before, "vanity_url_code", None)
        new = getattr(e.changes.after, "vanity_url_code", None)
        if _vanity_set_by_us.get(g.id) == new:
            return
        allowed = await handle_action(g, actor, "vanity_url", None, f"{old} → {new}", lambda: rv_vanity(g, old))
        was_preempted = g.id in _vanity_preempted
        _vanity_preempted.discard(g.id)
        if allowed:
            _vanity_allowed[g.id] = (new, time.time())
        if allowed and was_preempted and new:
            try:
                await set_vanity(g, new, "Antifast : changement de vanity autorisé")
            except discord.HTTPException:
                pass
        return
    kwargs = {}
    for attr in GUILD_EDIT_ATTRS:
        if hasattr(before, attr):
            kwargs[attr] = getattr(before, attr)
    if hasattr(before, "icon"):
        bk = latest_backup(g.id) or {}
        icon_b64 = bk.get("guild", {}).get("icon_b64")
        if icon_b64:
            kwargs["icon"] = base64.b64decode(icon_b64)
    if not kwargs:
        return
    await handle_action(g, actor, "guild_update", None, f"Serveur — {', '.join(kwargs)}", lambda: rv_edit_guild(g, kwargs))


async def h_webhook_create(e, g, actor, tid):
    await handle_action(g, actor, "webhook_create", tid, f"Webhook {tid}", lambda: rv_delete_webhook(g, tid))


async def h_webhook_delete(e, g, actor, tid):
    await handle_action(g, actor, "webhook_delete", tid, f"Webhook {tid}")


async def h_emoji_delete(e, g, actor, tid):
    snap = await wait_snapshot(_deleted_emojis, tid)
    emoji = snap[1] if snap else None
    await handle_action(g, actor, "emoji_delete", tid, f":{emoji.name if emoji else tid}:",
                        (lambda: rv_recreate_emoji(g, emoji)) if emoji else None)


async def h_disconnect(e, g, actor, tid):
    await handle_action(g, actor, "vdisconnect", None, f"{getattr(e.extra, 'count', 1)} membre(s) déconnecté(s)")


async def h_move(e, g, actor, tid):
    ch = getattr(e.extra, "channel", None)
    await handle_action(g, actor, "vmove", None,
                        f"{getattr(e.extra, 'count', 1)} membre(s) → {getattr(ch, 'mention', '?')}")


AUDIT_HANDLERS = {
    A.ban: h_ban, A.unban: h_unban, A.kick: h_kick, A.member_prune: h_prune,
    A.member_update: h_member_update, A.member_role_update: h_member_role_update,
    A.bot_add: h_bot_add,
    A.role_create: h_role_create, A.role_delete: h_role_delete, A.role_update: h_role_update,
    A.channel_create: h_channel_create, A.channel_delete: h_channel_delete, A.channel_update: h_channel_update,
    A.overwrite_create: h_overwrite, A.overwrite_update: h_overwrite, A.overwrite_delete: h_overwrite,
    A.guild_update: h_guild_update,
    A.webhook_create: h_webhook_create, A.webhook_delete: h_webhook_delete,
    A.emoji_delete: h_emoji_delete,
    A.member_disconnect: h_disconnect, A.member_move: h_move,
}


@bot.event
async def on_audit_log_entry_create(entry):
    handler = AUDIT_HANDLERS.get(entry.action)
    if handler is None:
        return
    actor = entry.user_id
    if actor is None or (bot.user and actor == bot.user.id):
        return
    try:
        await handler(entry, entry.guild, actor, getattr(entry.target, "id", None))
    except Exception as e:
        log.error(f"audit {entry.action}: {e}\n{traceback.format_exc()}")


# ========================= EVENTS GATEWAY (snapshots, vanity, bots) =========================

_ready_once = {"done": False}
_vanity_preempted = set()
_vanity_allowed = {}  # gid -> (code autorisé, ts)


@bot.event
async def on_ready():
    log.info(f"Bot connecté : {bot.user} ({bot.user.id}) · {len(bot.guilds)} serveur(s) · prefix {get_prefix_cached()}")
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="le serveur"))
    if _ready_once["done"]:
        return
    _ready_once["done"] = True
    reload_quotas()
    for g in bot.guilds:
        if not g.me.guild_permissions.view_audit_log:
            log.warning(f"⚠️ {g.name} : permission 'Voir les logs d'audit' manquante, protection inactive !")
        await do_backup(g, "startup")
    if not backup_loop.is_running():
        backup_loop.start()
    if not cleanup_loop.is_running():
        cleanup_loop.start()


def reload_quotas():
    """Recharge les quotas depuis la DB (un redémarrage ne remet pas les compteurs à zéro)."""
    cutoff = now_ts() - 7 * 86400
    n = 0
    for r in db_all("SELECT guild_id, user_id, action, ts FROM action_history WHERE counted = 1 AND ts >= ? ORDER BY ts",
                    (cutoff,)):
        _quota[(int(r["guild_id"]), int(r["user_id"]), r["action"])].append(float(r["ts"]))
        n += 1
    log.info(f"Quotas rechargés : {n} action(s)")


@bot.event
async def on_guild_join(guild):
    await do_backup(guild, "startup")


@bot.event
async def on_guild_channel_delete(channel):
    _deleted_channels[channel.id] = (time.time(), snapshot_channel(channel))


@bot.event
async def on_guild_role_delete(role):
    members = [m.id for m in role.guild.members if role.id in getattr(m, "_roles", [])]
    _deleted_roles[role.id] = (time.time(), snapshot_role(role), members)


@bot.event
async def on_guild_emojis_update(guild, before, after):
    after_ids = {e.id for e in after}
    for e in before:
        if e.id not in after_ids:
            _deleted_emojis[e.id] = (time.time(), e)


@bot.event
async def on_guild_update(before, after):
    """Vanity : revert immédiat sans attendre l'auteur (re-set si c'était autorisé)."""
    old, new = before.vanity_url_code, after.vanity_url_code
    if old == new or not old:
        return
    if _vanity_set_by_us.get(after.id) == new:
        return
    code, ts = _vanity_allowed.get(after.id, (None, 0))
    if code == new and time.time() - ts < 30:
        return  # l'audit log est arrivé avant : changement déjà validé
    _vanity_preempted.add(after.id)
    try:
        await set_vanity(after, old, "Antifast : revert urgence vanity URL")
        log.warning(f"[VANITY] {after.name} : {new!r} → {old!r} restaurée")
    except discord.HTTPException as e:
        log.error(f"[VANITY] revert échoué : {e}")


@bot.event
async def on_member_join(member):
    """Filet de sécurité : bot ajouté sans entrée d'audit reçue -> kick préventif."""
    if not member.bot or member.id in wl_bots(member.guild.id):
        return
    await asyncio.sleep(6)
    if (member.guild.id, member.id) in _bot_add_seen or member.guild.get_member(member.id) is None:
        return
    try:
        await member.kick(reason="Antifast : bot non whitelisté (auteur inconnu)")
        em = error_embed("🚨 Bot ajouté sans auteur identifié", f"{member.mention} ({member.id}) → **kick préventif**.")
        fire_log(member.guild, em, "bot_add")
    except discord.HTTPException:
        pass


# ========================= TÂCHES DE FOND =========================

@tasks.loop(minutes=BACKUP_INTERVAL_MIN)
async def backup_loop():
    for g in bot.guilds:
        await do_backup(g, "auto")
        await asyncio.sleep(1)


@backup_loop.before_loop
async def _bl_before():
    await bot.wait_until_ready()


@tasks.loop(minutes=10)
async def cleanup_loop():
    now = time.time()
    for store in (_deleted_channels, _deleted_roles, _deleted_emojis):
        for k in [k for k, v in store.items() if now - v[0] > 600]:
            del store[k]
    for k in list(_recent.keys()):
        dq = _recent[k]
        while dq and now - dq[0][0] > RECENT_REVERT_WINDOW:
            dq.popleft()
        if not dq:
            del _recent[k]
    for k in list(_quota.keys()):
        _prune_ts(_quota[k], now, 7 * 86400)
        if not _quota[k]:
            del _quota[k]
    for k in [k for k, t in _punished.items() if now - t > 3600]:
        del _punished[k]
    try:
        db_exec("DELETE FROM action_history WHERE ts < ?", (now_ts() - ACTION_HISTORY_DAYS * 86400,))
    except sqlite3.Error as e:
        log.warning(f"cleanup: {e}")


@cleanup_loop.before_loop
async def _cl_before():
    await bot.wait_until_ready()


# ========================= VUES DE BASE =========================

class OwnedView(discord.ui.View):
    def __init__(self, author_id, guild=None, min_rank=1, timeout=180):
        super().__init__(timeout=timeout)
        self.author_id = author_id
        self.guild = guild
        self.min_rank = min_rank
        self.message = None

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                f"Ce menu n'est pas à toi. Fais {get_prefix_cached()}help pour voir le tien.", ephemeral=True)
            return False
        if not has_min_rank(interaction.user.id, self.min_rank):
            await interaction.response.send_message("Tu n'as plus les permissions.", ephemeral=True)
            return False
        return True

    async def on_timeout(self):
        for item in self.children:
            item.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except discord.HTTPException:
                pass


async def ask_value(interaction, author_id, prompt, timeout=60):
    """Demande une valeur dans le salon (même système que le Bot BL)."""
    await interaction.response.send_message(prompt)

    def check(m):
        return m.author.id == author_id and m.channel.id == interaction.channel.id

    try:
        reply = await bot.wait_for("message", check=check, timeout=timeout)
    except asyncio.TimeoutError:
        try:
            await interaction.edit_original_response(content="⏱️ Temps écoulé, aucune valeur reçue.")
        except discord.HTTPException:
            pass
        return None
    val = reply.content.strip()
    for coro in (interaction.delete_original_response(), reply.delete()):
        try:
            await coro
        except discord.HTTPException:
            pass
    return val


class ConfirmView(OwnedView):
    def __init__(self, author_id, guild, min_rank, on_confirm, label="Confirmer"):
        super().__init__(author_id, guild, min_rank=min_rank, timeout=60)
        self.on_confirm = on_confirm
        self.confirm.label = label

    @discord.ui.button(label="Confirmer", style=discord.ButtonStyle.danger, emoji="✅")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(view=self)
        self.stop()
        await self.on_confirm(interaction)

    @discord.ui.button(label="Annuler", style=discord.ButtonStyle.secondary, emoji="✖️")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(embed=error_embed("✖️ Annulé", "Action annulée."), view=self)
        self.stop()


# ========================= HELP SYSTEM (filtré par rang) =========================

HELP_CATEGORIES = {
    "protection": {
        "label": "Protection", "title": "Protection",
        "subtitle": "Limites par rang, sanction, actions surveillées.",
        "sections": [
            ("🎛️", "Panneau", [
                ("limites",                              "Panneau interactif des limites", 4),
                ("setlimit <action> <rang> <max> <min>", "Modifier une limite",            4),
                ("punition [ban/kick/derank]",           "Sanction appliquée aux abus",    4),
            ]),
            ("👁️", "Consulter", [
                ("quota",                                "Tes quotas restants",            1),
                ("actions",                              "Actions surveillées + limites",  2),
            ]),
        ],
    },
    "rangs": {
        "label": "Rangs & bots", "title": "Rangs & bots",
        "subtitle": "Seuls les rangs peuvent faire des actions sensibles (dans leurs limites).",
        "sections": [
            ("📜", "Whitelist (Owner+)", [("wl [@user]", "Ajouter / voir la whitelist", 2),
                                          ("unwl @user", "Retirer de la whitelist", 2)]),
            ("👑", "Owner (Sys+)",       [("owner [@user]", "Ajouter / voir les owners", 3),
                                          ("unowner @user", "Retirer un owner", 3)]),
            ("⚙️", "Sys (Buyer)",        [("sys [@user]", "Ajouter / voir les sys", 4),
                                          ("unsys @user", "Retirer un sys", 4)]),
            ("🤖", "Bots", [("bot @bot", "Whitelister un bot (bypass total)", 4),
                           ("unbot @bot", "Retirer un bot", 4),
                           ("bots", "Bots whitelistés", 3)]),
            ("📋", "Vue d'ensemble", [("perms", "Tous les rangs attribués", 2)]),
        ],
    },
    "backups": {
        "label": "Backups", "title": "Backups",
        "subtitle": f"Sauvegarde auto toutes les {BACKUP_INTERVAL_MIN} min ({MAX_BACKUPS_PER_GUILD} gardées).",
        "sections": [
            ("📦", "Sauvegardes", [("backup", "Backup manuel", 3),
                                   ("backups", "Liste des backups", 3)]),
            ("♻️", "Restauration", [("restore [id]", "Recrée rôles, salons, perms et rôles des membres", 4)]),
        ],
    },
    "urgence": {
        "label": "Urgence", "title": "Urgence",
        "subtitle": "Réagir pendant une attaque.",
        "sections": [
            ("🔒", "Lockdown", [("lockdown on/off", "Retire les perms dangereuses de tous les rôles", 3)]),
            ("🚨", "Panic", [("panic [minutes]", "Ban les non-WL ayant agi récemment", 3)]),
            ("🔓", "Réparer", [("unban <id>", "Débannir (ex : faux positif)", 3)]),
        ],
    },
    "suivi": {
        "label": "Suivi", "title": "Suivi",
        "subtitle": "Historique des actions et des sanctions.",
        "sections": [
            ("📜", "Historique", [("history [@user]", "Dernières actions", 2),
                                  ("sanctions", "Dernières sanctions automatiques", 2)]),
        ],
    },
    "system": {
        "label": "Système", "title": "Système",
        "subtitle": "Configuration du bot.",
        "sections": [
            ("⚙️", "Buyer only", [
                ("categorie <id>",     "Crée les 8 salons de logs groupés", 4),
                ("uncategorie [delete]", "Retire la catégorie de logs",    4),
                ("setlog #salon",      "Salon de logs global (secours)",  4),
                ("prefix [nouveau]",   "Changer le prefix",               4),
                ("setemoji",           "Personnaliser les emojis",        4),
            ]),
        ],
    },
}


def _accessible_sections(key, rank):
    out = []
    for emoji, title, items in HELP_CATEGORIES[key]["sections"]:
        visible = [(s, d) for (s, d, mr) in items if rank >= mr]
        if visible:
            out.append((emoji, title, visible))
    return out


def help_category_visible(key, rank):
    return bool(_accessible_sections(key, rank))


def build_category_embed(key, rank, guild=None):
    p = get_prefix_cached()
    cat = HELP_CATEGORIES[key]
    em = discord.Embed(title=f"{get_emoji(f'help_cat_{key}')}  {cat['title']}",
                       description=cat.get("subtitle") or None, color=embed_color())
    apply_thumbnail(em, guild)
    sections = _accessible_sections(key, rank)
    if not sections:
        em.add_field(name="⛔ Aucune commande accessible", value="Tu n'as pas les permissions pour cette catégorie.", inline=False)
    for s_emoji, s_title, items in sections:
        em.add_field(name=f"{s_emoji} {s_title}", value="\n".join(f"{p}{s} — {d}" for s, d in items), inline=False)
    if key == "protection":
        em.add_field(name="💡 Fonctionnement",
                     value="Abus = **sanction** de l'auteur + **revert** de l'action et de toutes ses actions "
                           "des 30 dernières minutes.\nUn membre **sans rang** ne peut faire aucune action surveillée.",
                     inline=False)
    elif key == "rangs":
        em.add_field(name="💡 Règle importante",
                     value="Agir contre un rang **égal ou supérieur** au sien = sanction immédiate.\n"
                           "Whitelist les bots de confiance (ex : ton bot BL) avec `bot`.", inline=False)
    return em


def build_home_embed(rank, guild=None):
    p = get_prefix_cached()
    em = discord.Embed(
        title=f"{get_emoji('help_home_title')}  Bot Antifast",
        description=f"**Prefix :** {p} ・ **Ton rang :** {rank_name(rank)}\n\n"
                    f"*Choisis une catégorie ci-dessous pour voir ses commandes.*",
        color=embed_color())
    apply_thumbnail(em, guild)
    descs = {"protection": "Limites, sanction, quotas", "rangs": "Whitelist, owners, sys, bots",
             "backups": "Sauvegarde et restauration", "urgence": "Lockdown, panic, unban",
             "suivi": "Historique et sanctions", "system": "Config du bot"}
    for gname, keys in [("🛡️ Anti-nuke", ["protection", "urgence", "backups", "suivi"]),
                        ("🛠️ Staff & Admin", ["rangs", "system"])]:
        lines = [f"{get_emoji(f'help_cat_{k}')} **{HELP_CATEGORIES[k]['label']}** — {descs[k]}"
                 for k in keys if help_category_visible(k, rank)]
        if lines:
            em.add_field(name=gname, value="\n".join(lines), inline=False)
    if guild:
        active = len(ACTIONS) - len(get_disabled_actions() & set(ACTIONS))
        status = f"**{active}/{len(ACTIONS)}** actions surveillées ・ Sanction : **{PUNISH_MODES[get_punish_mode()]}**"
        if db_one("SELECT 1 FROM lockdown_state WHERE guild_id = ?", (str(guild.id),)):
            status += "\n🔒 **Lockdown actif**"
        if not guild.me.guild_permissions.view_audit_log:
            status += "\n⚠️ **Permission « Voir les logs d'audit » manquante : protection inactive !**"
        em.add_field(name="📊 Statut", value=status, inline=False)
    return em


class HelpDropdown(discord.ui.Select):
    def __init__(self, user_rank, guild=None):
        self.user_rank = user_rank
        self.guild = guild
        options = [discord.SelectOption(label="Accueil", emoji="🏠", value="home")]
        for key, cat in HELP_CATEGORIES.items():
            if help_category_visible(key, user_rank):
                options.append(discord.SelectOption(label=cat["label"], value=key,
                                                    emoji=_emoji_for_select(get_emoji(f"help_cat_{key}"))))
        super().__init__(placeholder="📂 Choisis une catégorie...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        key = self.values[0]
        em = build_home_embed(self.user_rank, self.guild) if key == "home" else build_category_embed(key, self.user_rank, self.guild)
        await interaction.response.edit_message(embed=em, view=self.view)


class HelpView(OwnedView):
    def __init__(self, author_id, user_rank, guild=None):
        super().__init__(author_id, guild, min_rank=1, timeout=120)
        self.add_item(HelpDropdown(user_rank, guild))


@bot.command(name="help")
async def _help(ctx):
    rank = get_rank_db(ctx.author.id)
    if rank < 1:
        return
    view = HelpView(ctx.author.id, rank, ctx.guild)
    view.message = await ctx.send(embed=build_home_embed(rank, ctx.guild), view=view)


# ========================= PANNEAU LIMITES =========================

RANK_SHORT = {0: "Aucun", 1: "WL", 2: "Owner", 3: "Sys"}


def short_limits(action):
    parts = []
    for r in (0, 1, 2, 3):
        m, w = get_limit_for(action, r)
        if m > 0:
            parts.append(f"{RANK_SHORT[r]} {m}/{w}m")
    return " · ".join(parts) or "Buyer uniquement"


def build_limits_embed(guild):
    on, off = get_emoji("status_on"), get_emoji("status_off")
    disabled = get_disabled_actions()
    em = discord.Embed(
        title=f"{get_emoji('panel_title')}  Antifast · Limites",
        description=f"Choisis une action pour modifier ses limites par rang.\n"
                    f"**Sanction :** {PUNISH_MODES[get_punish_mode()]} ・ *Buyer = illimité, Aucun rang = interdit par défaut*",
        color=embed_color())
    for gname, keys in ACTION_GROUPS:
        lines = [f"{off if k in disabled else on} {ACTIONS[k][1]} `{k}` — {short_limits(k)}" for k in keys]
        em.add_field(name=gname, value="\n".join(lines)[:1024], inline=False)
    em.add_field(name="🤖 Toujours actif", value="`bot_add` (bot non whitelisté) ・ `tamper` (bot / hiérarchie)", inline=False)
    apply_thumbnail(em, guild)
    return em


def build_action_embed(action, guild):
    label, emoji, _g = ACTIONS[action]
    on = action not in get_disabled_actions()
    em = discord.Embed(title=f"{emoji}  {label}",
                       description=f"`{action}` ・ Surveillance : {get_emoji('status_on') + ' **active**' if on else get_emoji('status_off') + ' **coupée**'}\n"
                                   f"*Choisis un rang puis envoie `max minutes` (ex : `3 30`) ou `0` pour interdire.*",
                       color=embed_color())
    for r in (0, 1, 2, 3):
        em.add_field(name=rank_name(r), value=fmt_limit(get_limit_for(action, r)), inline=True)
    em.add_field(name="Buyer", value="illimité", inline=True)
    apply_thumbnail(em, guild)
    return em


class ActionSelect(discord.ui.Select):
    def __init__(self):
        disabled = get_disabled_actions()
        options = [discord.SelectOption(label=ACTIONS[k][0][:100], value=k, emoji=_emoji_for_select(ACTIONS[k][1]),
                                        description=(("OFF — " if k in disabled else "") + short_limits(k))[:100])
                   for _g, keys in ACTION_GROUPS for k in keys]
        super().__init__(placeholder="⏱️ Choisis une action...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        view = ActionView(self.view.author_id, self.view.guild, self.values[0])
        await interaction.response.edit_message(embed=build_action_embed(self.values[0], self.view.guild), view=view)
        view.message = interaction.message


class LimitsView(OwnedView):
    def __init__(self, author_id, guild):
        super().__init__(author_id, guild, min_rank=4)
        self.add_item(ActionSelect())
        self.punish_btn.label = f"Sanction : {get_punish_mode()}"

    async def _refresh(self, interaction):
        view = LimitsView(self.author_id, self.guild)
        await interaction.response.edit_message(embed=build_limits_embed(self.guild), view=view)
        view.message = interaction.message

    @discord.ui.button(label="Sanction", style=discord.ButtonStyle.primary, emoji="⚖️", row=1)
    async def punish_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        modes = list(PUNISH_MODES)
        set_config("punish", modes[(modes.index(get_punish_mode()) + 1) % len(modes)])
        await self._refresh(interaction)

    @discord.ui.button(label="Tout réinitialiser", style=discord.ButtonStyle.danger, emoji="♻️", row=1)
    async def reset_all(self, interaction: discord.Interaction, button: discord.ui.Button):
        reset_limits()
        set_config("disabled_actions", "[]")
        await self._refresh(interaction)
        await internal_log(self.guild, "Limites réinitialisées", interaction.user, color=0xfaa61a)


class RankSelect(discord.ui.Select):
    def __init__(self, action):
        self.action = action
        options = [discord.SelectOption(label=rank_name(r), value=str(r),
                                        description=f"Actuel : {fmt_limit(get_limit_for(action, r)).replace('**', '')}"[:100])
                   for r in (0, 1, 2, 3)]
        super().__init__(placeholder="👥 Choisis un rang à modifier...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        rank = int(self.values[0])
        panel_msg = interaction.message
        author_id, guild, action = self.view.author_id, self.view.guild, self.action
        val = await ask_value(interaction, author_id,
                              f"📨 Envoie la limite **{ACTIONS[action][0]}** pour **{rank_name(rank)}** : "
                              f"`max minutes` (ex : `3 30`) ou `0` pour interdire. *(60 secondes)*")
        if val is None:
            return
        parts = val.split()
        ok = False
        if parts and parts[0].isdigit():
            m = int(parts[0])
            w = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 60
            if 0 <= m <= 1000 and 1 <= w <= 10080:
                set_limit(action, rank, m, w if m > 0 else 0)
                ok = True
                await internal_log(guild, "Limite modifiée", interaction.user,
                                   f"`{action}` / {rank_name(rank)} → {fmt_limit(get_limit_for(action, rank))}")
        if not ok:
            try:
                await interaction.followup.send("❌ Format invalide (ex : `3 30`), aucune modification.", ephemeral=True)
            except discord.HTTPException:
                pass
        try:
            view = ActionView(author_id, guild, action)
            await panel_msg.edit(embed=build_action_embed(action, guild), view=view)
            view.message = panel_msg
        except discord.HTTPException:
            pass


class ActionView(OwnedView):
    def __init__(self, author_id, guild, action):
        super().__init__(author_id, guild, min_rank=4)
        self.action = action
        self.add_item(RankSelect(action))
        on = action not in get_disabled_actions()
        self.toggle_btn.label = "Couper la surveillance" if on else "Activer la surveillance"
        self.toggle_btn.style = discord.ButtonStyle.danger if on else discord.ButtonStyle.success

    async def _refresh(self, interaction):
        view = ActionView(self.author_id, self.guild, self.action)
        await interaction.response.edit_message(embed=build_action_embed(self.action, self.guild), view=view)
        view.message = interaction.message

    @discord.ui.button(label="Retour", style=discord.ButtonStyle.secondary, emoji="◀️", row=1)
    async def back(self, interaction: discord.Interaction, button: discord.ui.Button):
        view = LimitsView(self.author_id, self.guild)
        await interaction.response.edit_message(embed=build_limits_embed(self.guild), view=view)
        view.message = interaction.message

    @discord.ui.button(label="Surveillance", style=discord.ButtonStyle.danger, emoji="👁️", row=1)
    async def toggle_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        on = toggle_action(self.action)
        await self._refresh(interaction)
        await internal_log(self.guild, "Surveillance modifiée", interaction.user,
                           f"`{self.action}` → {'**active**' if on else '**coupée**'}", color=0xfaa61a)

    @discord.ui.button(label="Défaut", style=discord.ButtonStyle.secondary, emoji="♻️", row=1)
    async def reset_one(self, interaction: discord.Interaction, button: discord.ui.Button):
        reset_limits(self.action)
        await self._refresh(interaction)


@bot.command(name="limites", aliases=["limite", "limits", "panel"])
async def _limites(ctx):
    if not await gate(ctx, 4):
        return
    view = LimitsView(ctx.author.id, ctx.guild)
    view.message = await ctx.send(embed=build_limits_embed(ctx.guild), view=view)


RANK_ARGS = {"aucun": 0, "none": 0, "0": 0, "wl": 1, "whitelist": 1, "1": 1, "owner": 2, "2": 2, "sys": 3, "3": 3}


@bot.command(name="setlimit")
async def _setlimit(ctx, action: str = None, rang: str = None, max_actions: int = None, minutes: int = None):
    if not await gate(ctx, 4):
        return
    p = get_prefix_cached()
    action = (action or "").lower()
    if action not in ACTIONS or (rang or "").lower() not in RANK_ARGS or max_actions is None:
        return await ctx.send(embed=error_embed(
            "❌ Usage", f"{p}setlimit <action> <aucun/wl/owner/sys> <max> <minutes>\n"
                       f"Ex : {p}setlimit ban wl 3 20 ・ {p}setlimit ban wl 0 (interdit)\n\n"
                       f"**Actions :** {', '.join(ACTIONS)}"))
    rank = RANK_ARGS[rang.lower()]
    minutes = minutes or 60
    if not (0 <= max_actions <= 1000 and 1 <= minutes <= 10080):
        return await ctx.send(embed=error_embed("❌ Hors limites", "max : 0–1000 ・ minutes : 1–10080"))
    set_limit(action, rank, max_actions, minutes if max_actions else 0)
    txt = f"`{action}` pour **{rank_name(rank)}** : {fmt_limit(get_limit_for(action, rank))}"
    await ctx.send(embed=success_embed("✅ Limite modifiée", txt))
    await internal_log(ctx.guild, "Limite modifiée", ctx.author, txt)


@bot.command(name="punition", aliases=["sanction"])
async def _punition(ctx, mode: str = None):
    if not await gate(ctx, 4):
        return
    if mode is None or mode.lower() not in PUNISH_MODES:
        return await ctx.send(embed=info_embed(
            "⚖️ Sanction actuelle", f"{PUNISH_MODES[get_punish_mode()]}\n\n"
                                   f"Usage : {get_prefix_cached()}punition <ban/kick/derank>\n"
                                   f"*Si le ban/kick échoue (rôle trop haut), le bot retire automatiquement les rôles.*"))
    set_config("punish", mode.lower())
    await ctx.send(embed=success_embed("✅ Sanction modifiée", PUNISH_MODES[mode.lower()]))
    await internal_log(ctx.guild, "Sanction modifiée", ctx.author, PUNISH_MODES[mode.lower()])


@bot.command(name="actions")
async def _actions(ctx):
    if not await gate(ctx, 2):
        return
    em = build_limits_embed(ctx.guild)
    em.description = f"Actions surveillées et limites par rang. **Sanction :** {PUNISH_MODES[get_punish_mode()]}"
    await ctx.send(embed=em)


@bot.command(name="quota")
async def _quota_cmd(ctx, *, user_input: str = None):
    if not await gate(ctx, 1):
        return
    uid, display = ctx.author.id, ctx.author
    if user_input and has_min_rank(ctx.author.id, 2):
        display, uid = await resolve_user_or_id(ctx, user_input)
        if uid is None:
            return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    rank = get_rank_db(uid)
    name = getattr(display, "display_name", None) or f"ID {uid}"
    em = discord.Embed(title=f"📊 Quotas — {name}", description=f"Rang : **{rank_name(rank)}**", color=embed_color())
    if rank >= 4:
        em.description += "\nIllimité sur toutes les actions."
        return await ctx.send(embed=em)
    now = time.time()
    for gname, keys in ACTION_GROUPS:
        lines = []
        for k in keys:
            m, w = get_limit_for(k, rank)
            if m <= 0:
                lines.append(f"✖ `{k}` — interdit")
                continue
            dq = _quota.get((ctx.guild.id, uid, k), deque())
            used = sum(1 for t in dq if now - t <= w * 60)
            bar = "🟢" if m - used > m * 0.5 else ("🟡" if used < m else "🔴")
            lines.append(f"{bar} `{k}` — **{used}/{m}** ({w} min)")
        em.add_field(name=gname, value="\n".join(lines)[:1024], inline=False)
    await ctx.send(embed=em)


# ========================= RANGS =========================

async def _rank_list(ctx, level, min_rank, title):
    if not await gate(ctx, min_rank):
        return
    ids = get_ranks_by_level(level)
    if not ids:
        return await ctx.send(embed=info_embed(f"📋 {title}", "Aucun utilisateur."))
    await ctx.send(embed=info_embed(f"📋 {title} ({len(ids)})", "\n".join(f"<@{u}>" for u in ids)[:4000]))


async def _rank_add(ctx, user_input, level, min_rank, label):
    if not await gate(ctx, min_rank):
        return
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    cur = get_rank_db(uid)
    if cur == level:
        return await ctx.send(embed=error_embed(f"Déjà {label}", f"{format_user_display(display, uid)} est déjà **{label}**."))
    if cur > level:
        return await ctx.send(embed=error_embed("❌ Erreur", f"{format_user_display(display, uid)} a un rang supérieur."))
    set_rank_db(uid, level)
    await ctx.send(embed=success_embed(f"✅ {label} ajouté", f"{format_user_display(display, uid)} a été ajouté en **{label}**."))
    await send_log(ctx.guild, f"{label} ajouté", ctx.author, display, uid, color=0x43b581)


async def _rank_remove(ctx, user_input, level, min_rank, label):
    if not await gate(ctx, min_rank):
        return
    if not user_input:
        return await ctx.send(embed=error_embed("Argument manquant", "Mention, ID ou nom requis."))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
    if get_rank_db(uid) != level:
        return await ctx.send(embed=error_embed(f"Pas {label}", f"{format_user_display(display, uid)} n'est pas **{label}**."))
    set_rank_db(uid, 0)
    await ctx.send(embed=success_embed(f"✅ {label} retiré", f"{format_user_display(display, uid)} a été retiré des **{label}**."))
    await send_log(ctx.guild, f"{label} retiré", ctx.author, display, uid, color=0xfaa61a)


@bot.command(name="sys")
async def _sys(ctx, *, user_input: str = None):
    if user_input is None:
        return await _rank_list(ctx, 3, 4, "Liste Sys")
    await _rank_add(ctx, user_input, 3, 4, "Sys")


@bot.command(name="unsys")
async def _unsys(ctx, *, user_input: str = None):
    await _rank_remove(ctx, user_input, 3, 4, "Sys")


@bot.command(name="owner")
async def _owner(ctx, *, user_input: str = None):
    if user_input is None:
        return await _rank_list(ctx, 2, 3, "Liste Owner")
    await _rank_add(ctx, user_input, 2, 3, "Owner")


@bot.command(name="unowner")
async def _unowner(ctx, *, user_input: str = None):
    await _rank_remove(ctx, user_input, 2, 3, "Owner")


@bot.command(name="wl")
async def _wl(ctx, *, user_input: str = None):
    if user_input is None:
        return await _rank_list(ctx, 1, 2, "Whitelist")
    await _rank_add(ctx, user_input, 1, 2, "Whitelist")


@bot.command(name="unwl")
async def _unwl(ctx, *, user_input: str = None):
    await _rank_remove(ctx, user_input, 1, 2, "Whitelist")


@bot.command(name="perms")
async def _perms(ctx):
    if not await gate(ctx, 2):
        return
    em = info_embed("📋 Rangs configurés")

    def fmt(ids):
        return ", ".join(f"<@{u}>" for u in ids)[:1024] or "*aucun*"

    em.add_field(name=f"👑 Buyer ({len(_buyer_cache)})", value=fmt(_buyer_cache), inline=False)
    for lvl, emoji in ((3, "⚙️"), (2, "👑"), (1, "📜")):
        ids = get_ranks_by_level(lvl)
        em.add_field(name=f"{emoji} {rank_name(lvl)} ({len(ids)})", value=fmt(ids), inline=False)
    bots_ = wl_bots(ctx.guild.id)
    em.add_field(name=f"🤖 Bots whitelistés ({len(bots_)})", value=fmt(bots_), inline=False)
    apply_thumbnail(em, ctx.guild)
    await ctx.send(embed=em)


# ========================= BOTS WHITELIST =========================

@bot.command(name="bot")
async def _bot(ctx, *, user_input: str = None):
    if not await gate(ctx, 4):
        return
    if not user_input:
        return await ctx.send(embed=error_embed("Usage", f"{get_prefix_cached()}bot <@bot|id>\n\n"
                                                         f"⚠️ Un bot whitelisté peut **tout** faire sans être sanctionné."))
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("❌ Introuvable", "Mention ou ID requis."))
    user = display if display is not None else None
    if user is None or not getattr(user, "bot", False):
        try:
            user = await bot.fetch_user(uid)
        except discord.HTTPException:
            user = None
    if not user or not user.bot:
        return await ctx.send(embed=error_embed("❌ Pas un bot", f"<@{uid}> n'est pas un compte bot."))
    if uid in wl_bots(ctx.guild.id):
        return await ctx.send(embed=error_embed("Déjà whitelisté", f"🤖 **{user.name}** est déjà whitelisté."))
    wl_bot_add(ctx.guild.id, uid, user.name, ctx.author.id)
    await ctx.send(embed=success_embed("✅ Bot whitelisté", f"🤖 **{user.name}** ({uid}) ignore maintenant toutes les limites."))
    await internal_log(ctx.guild, "Bot whitelisté", ctx.author, f"🤖 **{user.name}** ({uid})", color=0x43b581)


@bot.command(name="unbot")
async def _unbot(ctx, *, user_input: str = None):
    if not await gate(ctx, 4):
        return
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("Argument manquant", "Mention ou ID requis."))
    if not wl_bot_remove(ctx.guild.id, uid):
        return await ctx.send(embed=error_embed("Pas whitelisté", f"<@{uid}> n'est pas whitelisté."))
    await ctx.send(embed=success_embed("✅ Bot retiré", f"🤖 <@{uid}> n'est plus whitelisté."))
    await internal_log(ctx.guild, "Bot retiré", ctx.author, f"<@{uid}> ({uid})", color=0xfaa61a)


@bot.command(name="bots")
async def _bots(ctx):
    if not await gate(ctx, 3):
        return
    rows = db_all("SELECT * FROM wl_bots WHERE guild_id = ? ORDER BY ts", (str(ctx.guild.id),))
    if not rows:
        return await ctx.send(embed=info_embed("🤖 Bots whitelistés", f"Aucun. {get_prefix_cached()}bot @bot pour en ajouter."))
    lines = [f"🤖 <@{r['bot_id']}> ({r['bot_id']}) — par <@{r['added_by']}> <t:{r['ts']}:d>" for r in rows]
    await ctx.send(embed=info_embed(f"🤖 Bots whitelistés ({len(rows)})", "\n".join(lines)[:4000]))


# ========================= BACKUPS =========================

@bot.command(name="backup")
async def _backup(ctx):
    if not await gate(ctx, 3):
        return
    bid, err = await do_backup(ctx.guild, "manual")
    if not bid:
        return await ctx.send(embed=error_embed("❌ Backup échoué", f"{err}"))
    data = _latest_backup[ctx.guild.id]
    await ctx.send(embed=success_embed("✅ Backup effectué",
                                       f"Backup **#{bid}** : {len(data['roles'])} rôles, {len(data['channels'])} salons, "
                                       f"{len(data['members'])} membres."))
    await internal_log(ctx.guild, "Backup manuel", ctx.author, f"Backup #{bid}")


@bot.command(name="backups", aliases=["backuplist"])
async def _backups(ctx):
    if not await gate(ctx, 3):
        return
    rows = db_all("SELECT id, ts, trigger FROM backups WHERE guild_id = ? ORDER BY ts DESC", (str(ctx.guild.id),))
    if not rows:
        return await ctx.send(embed=info_embed("📦 Backups", "Aucun backup."))
    icons = {"auto": "🔄", "manual": "✋", "startup": "🚀"}
    lines = [f"{icons.get(r['trigger'], '📦')} **#{r['id']}** ・ <t:{r['ts']}:f> (<t:{r['ts']}:R>) ・ *{r['trigger']}*" for r in rows]
    em = info_embed(f"📦 Backups ({len(rows)})", "\n".join(lines))
    em.set_footer(text=f"Auto toutes les {BACKUP_INTERVAL_MIN} min · {MAX_BACKUPS_PER_GUILD} gardés · {get_prefix_cached()}restore [id]")
    await ctx.send(embed=em)


async def run_restore(guild, data, author):
    """Recrée ce qui manque : rôles -> catégories -> salons (perms remappées) -> rôles des membres."""
    reason = f"Antifast restore par {author}"
    id_map, created_roles, created_channels, errors = {}, [], 0, []

    for r in sorted(data.get("roles", []), key=lambda x: x["position"]):
        if r.get("default") or r.get("managed"):
            continue
        existing = guild.get_role(int(r["id"]))
        if existing:
            id_map[r["id"]] = existing
            continue
        try:
            role, _ = await recreate_role(guild, r, None, reason)
            id_map[r["id"]] = role
            created_roles.append(r["id"])
            await asyncio.sleep(0.3)
        except discord.HTTPException as e:
            errors.append(f"Rôle {r['name']} : {type(e).__name__}")

    chans = data.get("channels", [])
    for c in sorted(chans, key=lambda x: (x["type"] != "category", x["position"])):
        existing = guild.get_channel(int(c["id"]))
        if existing:
            id_map[c["id"]] = existing
            continue
        try:
            snap = dict(c)
            snap.pop("children", None)
            id_map[c["id"]] = await recreate_channel(guild, snap, id_map, reason)
            created_channels += 1
            await asyncio.sleep(0.3)
        except discord.HTTPException as e:
            errors.append(f"Salon {c['name']} : {type(e).__name__}")

    given = 0
    if created_roles:
        new_set = set(created_roles)
        for uid, rids in list(data.get("members", {}).items()):
            if given >= MAX_ROLE_REASSIGN:
                break
            m = guild.get_member(int(uid))
            to_add = [id_map[r] for r in rids if r in new_set and r in id_map]
            if m and to_add:
                try:
                    await m.add_roles(*to_add, reason=reason)
                    given += 1
                    await asyncio.sleep(0.2)
                except discord.HTTPException:
                    pass
    return len(created_roles), created_channels, given, errors


@bot.command(name="restore", aliases=["revert"])
async def _restore(ctx, backup_id: int = None):
    if not await gate(ctx, 4):
        return
    if backup_id is None:
        row = db_one("SELECT id, ts, data FROM backups WHERE guild_id = ? ORDER BY ts DESC LIMIT 1", (str(ctx.guild.id),))
    else:
        row = db_one("SELECT id, ts, data FROM backups WHERE guild_id = ? AND id = ?", (str(ctx.guild.id), backup_id))
    if not row:
        return await ctx.send(embed=error_embed("❌ Backup introuvable", f"{get_prefix_cached()}backups pour la liste."))
    data = json.loads(row["data"])
    missing_r = sum(1 for r in data["roles"] if not r.get("default") and not r.get("managed") and not ctx.guild.get_role(int(r["id"])))
    missing_c = sum(1 for c in data["channels"] if not ctx.guild.get_channel(int(c["id"])))

    async def go(interaction):
        await interaction.followup.send(embed=info_embed("⏳ Restauration en cours...", "Ça peut prendre un moment."))
        r, c, g, errs = await run_restore(ctx.guild, data, ctx.author)
        em = success_embed("✅ Restauration terminée",
                           f"**Backup :** #{row['id']}\n**Rôles recréés :** {r}\n**Salons recréés :** {c}\n"
                           f"**Membres re-rôlés :** {g}\n**Erreurs :** {len(errs)}")
        if errs:
            em.add_field(name="Erreurs", value="\n".join(errs[:10])[:1024], inline=False)
        await interaction.followup.send(embed=em)
        await internal_log(ctx.guild, "Restauration", ctx.author, f"Backup #{row['id']} : {r} rôles, {c} salons, {g} membres",
                           color=0x9b59b6)

    em = warn_embed("⚠️ Confirmation de restauration",
                    f"Backup **#{row['id']}** du <t:{row['ts']}:f> (<t:{row['ts']}:R>).\n\n"
                    f"**Rôles manquants :** {missing_r}\n**Salons manquants :** {missing_c}\n\n"
                    f"Seuls les éléments **manquants** sont recréés (avec leurs permissions), "
                    f"puis les rôles recréés sont redonnés aux membres. Rien d'existant n'est modifié.")
    view = ConfirmView(ctx.author.id, ctx.guild, 4, go, label="Restaurer")
    view.message = await ctx.send(embed=em, view=view)


# ========================= URGENCE =========================

def protected_role_ids(guild):
    ids = set()
    for uid in list(_buyer_cache) + get_ranks_by_level(3):
        m = guild.get_member(int(uid))
        if m:
            ids.update(r.id for r in m.roles if r.permissions.value & DANGER_MASK)
    return ids


@bot.command(name="lockdown")
async def _lockdown(ctx, state: str = None):
    if not await gate(ctx, 3):
        return
    g = ctx.guild
    cur = db_one("SELECT * FROM lockdown_state WHERE guild_id = ?", (str(g.id),))
    state = (state or "").lower()
    if state not in ("on", "off"):
        if cur:
            return await ctx.send(embed=error_embed("🔒 Lockdown ACTIF", f"Depuis <t:{cur['ts']}:R> par <@{cur['enabled_by']}>."))
        return await ctx.send(embed=info_embed("🔓 Lockdown inactif", f"{get_prefix_cached()}lockdown on/off"))

    if state == "on":
        if cur:
            return await ctx.send(embed=error_embed("Déjà actif", "Le lockdown est déjà activé."))
        msg = await ctx.send(embed=info_embed("⏳ Lockdown en cours...", "Retrait des permissions dangereuses."))
        saved, changed, skipped = {}, 0, 0
        protect = protected_role_ids(g)
        for role in g.roles:
            if role.managed or role.id in protect or not (role.permissions.value & DANGER_MASK):
                continue
            if role >= g.me.top_role:
                skipped += 1
                continue
            saved[str(role.id)] = role.permissions.value
            try:
                await role.edit(permissions=discord.Permissions(role.permissions.value & ~DANGER_MASK),
                                reason=f"Antifast lockdown par {ctx.author}")
                changed += 1
                await asyncio.sleep(0.25)
            except discord.HTTPException:
                skipped += 1
        db_exec("INSERT OR REPLACE INTO lockdown_state VALUES (?, ?, ?, ?)",
                (str(g.id), str(ctx.author.id), now_ts(), json.dumps(saved)))
        await msg.edit(embed=error_embed("🔒 LOCKDOWN ACTIVÉ",
                                         f"**{changed}** rôle(s) ont perdu leurs perms dangereuses "
                                         f"({', '.join(DANGER_PERMS)}).\n"
                                         f"Rôles des Buyer/Sys épargnés." + (f"\n⚠️ {skipped} rôle(s) non modifiables." if skipped else "")))
        await internal_log(g, "Lockdown ACTIVÉ", ctx.author, f"{changed} rôle(s)", color=0xf04747)
    else:
        if not cur:
            return await ctx.send(embed=error_embed("Pas actif", "Le lockdown n'est pas activé."))
        restored = 0
        for rid, perms in json.loads(cur["saved"] or "{}").items():
            role = g.get_role(int(rid))
            if role:
                try:
                    await role.edit(permissions=discord.Permissions(int(perms)), reason=f"Antifast lockdown off par {ctx.author}")
                    restored += 1
                    await asyncio.sleep(0.25)
                except discord.HTTPException:
                    pass
        db_exec("DELETE FROM lockdown_state WHERE guild_id = ?", (str(g.id),))
        await ctx.send(embed=success_embed("🔓 Lockdown désactivé", f"**{restored}** rôle(s) restauré(s)."))
        await internal_log(g, "Lockdown DÉSACTIVÉ", ctx.author, f"{restored} rôle(s) restauré(s)", color=0x43b581)


@bot.command(name="panic")
async def _panic(ctx, minutes: int = 10):
    if not await gate(ctx, 3):
        return
    minutes = max(1, min(minutes, 1440))
    rows = db_all("SELECT DISTINCT user_id FROM action_history WHERE guild_id = ? AND ts >= ?",
                  (str(ctx.guild.id), now_ts() - minutes * 60))
    targets = [int(r["user_id"]) for r in rows
               if get_rank_db(r["user_id"]) < 1 and int(r["user_id"]) not in wl_bots(ctx.guild.id)
               and int(r["user_id"]) != bot.user.id]
    if not targets:
        return await ctx.send(embed=info_embed("🚨 Panic", f"Aucun non-WL n'a agi dans les **{minutes}** dernières minutes."))

    async def go(interaction):
        banned = 0
        for uid in targets:
            try:
                await ctx.guild.ban(discord.Object(id=uid), reason=f"Antifast PANIC par {ctx.author}", delete_message_seconds=0)
                banned += 1
                await asyncio.sleep(0.2)
            except discord.HTTPException:
                pass
        await interaction.followup.send(embed=error_embed("🚨 PANIC EXÉCUTÉ", f"**{banned}/{len(targets)}** banni(s)."))
        await internal_log(ctx.guild, "PANIC", ctx.author, f"{banned} banni(s)", color=0xf04747)

    em = warn_embed("⚠️ MODE PANIQUE",
                    f"**{len(targets)}** non-WL ont fait une action surveillée dans les **{minutes}** dernières minutes :\n"
                    + ", ".join(f"<@{u}>" for u in targets[:30]) + ("..." if len(targets) > 30 else "")
                    + "\n\nIls seront **bannis**. Les rangs et bots whitelistés sont épargnés.")
    view = ConfirmView(ctx.author.id, ctx.guild, 3, go, label="Bannir")
    view.message = await ctx.send(embed=em, view=view)


@bot.command(name="unban")
async def _unban(ctx, *, user_input: str = None):
    if not await gate(ctx, 3):
        return
    display, uid = await resolve_user_or_id(ctx, user_input)
    if uid is None:
        return await ctx.send(embed=error_embed("Argument manquant", "ID requis."))
    try:
        await ctx.guild.unban(discord.Object(id=uid), reason=f"Antifast unban par {ctx.author}")
    except discord.NotFound:
        return await ctx.send(embed=error_embed("Pas banni", f"{format_user_display(display, uid)} n'est pas banni."))
    _punished.pop((ctx.guild.id, uid), None)
    await ctx.send(embed=success_embed("✅ Débanni", f"{format_user_display(display, uid)} a été débanni."))
    await send_log(ctx.guild, "Unban (commande)", ctx.author, display, uid, color=0x43b581)


# ========================= SUIVI =========================

@bot.command(name="history")
async def _history(ctx, *, user_input: str = None):
    if not await gate(ctx, 2):
        return
    if user_input:
        display, uid = await resolve_user_or_id(ctx, user_input)
        if uid is None:
            return await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Mention, ID ou nom requis."))
        rows = db_all("SELECT * FROM action_history WHERE guild_id = ? AND user_id = ? ORDER BY ts DESC LIMIT 20",
                      (str(ctx.guild.id), str(uid)))
        title = f"📜 Historique — {getattr(display, 'display_name', None) or uid}"
    else:
        rows = db_all("SELECT * FROM action_history WHERE guild_id = ? ORDER BY ts DESC LIMIT 20", (str(ctx.guild.id),))
        title = "📜 Historique du serveur"
    if not rows:
        return await ctx.send(embed=info_embed(title, "Aucune action enregistrée."))
    icons = {"ok": "✅", "buyer": "👑", "bot": "🤖", "violation": "🚨"}
    lines = [f"{icons.get(r['status'], '•')} <t:{r['ts']}:R> <@{r['user_id']}> `{r['action']}`"
             + (f" → {r['label'][:60]}" if r.get("label") else "") for r in rows]
    await ctx.send(embed=info_embed(title, "\n".join(lines)[:4000]))


@bot.command(name="sanctions", aliases=["autobans"])
async def _sanctions(ctx):
    if not await gate(ctx, 2):
        return
    rows = db_all("SELECT * FROM auto_sanctions WHERE guild_id = ? ORDER BY ts DESC LIMIT 15", (str(ctx.guild.id),))
    if not rows:
        return await ctx.send(embed=info_embed("🚨 Sanctions automatiques", "Aucune."))
    lines = [f"<t:{r['ts']}:R> <@{r['user_id']}> `{r['action']}` — {r['result'][:60]} ・ {r['reverts']} revert(s)" for r in rows]
    await ctx.send(embed=info_embed(f"🚨 Sanctions automatiques ({len(rows)})", "\n".join(lines)[:4000]))


# ========================= SYSTÈME =========================

@bot.command(name="prefix")
async def _prefix(ctx, new_prefix: str = None):
    if not await gate(ctx, 4):
        return
    if not new_prefix:
        return await ctx.send(embed=info_embed("Prefix actuel", get_prefix_cached()))
    set_config("prefix", new_prefix)
    await ctx.send(embed=success_embed("✅ Prefix modifié", f"Nouveau prefix : {new_prefix}"))


@bot.command(name="setlog")
async def _setlog(ctx, channel: discord.TextChannel = None):
    if not await gate(ctx, 4):
        return
    if not channel:
        return await ctx.send(embed=error_embed("Argument manquant", "Mentionne un salon."))
    set_log_channel(ctx.guild.id, channel.id)
    await ctx.send(embed=success_embed("✅ Salon de logs défini",
                                       f"Les logs sans salon dédié iront dans {channel.mention}.\n"
                                       f"Pour un salon par thème : {get_prefix_cached()}categorie <id>."))


@bot.command(name="categorie", aliases=["category"])
async def _categorie(ctx, *, category_input: str = None):
    if not await gate(ctx, 4):
        return
    g = ctx.guild
    if not category_input:
        cur = db_one("SELECT * FROM log_category WHERE guild_id = ?", (str(g.id),))
        if not cur:
            return await ctx.send(embed=info_embed("📂 Catégorie de logs", f"Aucune. {get_prefix_cached()}categorie <id_catégorie>"))
        mapping = get_action_channels(g.id)
        lines = sorted({f"<#{cid}>" for cid in mapping.values()})
        return await ctx.send(embed=info_embed("📂 Catégorie de logs",
                                               f"**Catégorie :** <#{cur['category_id']}>\n**Salons :**\n" + "\n".join(lines)))
    clean = category_input.strip("<#>")
    cat = g.get_channel(int(clean)) if clean.isdigit() else discord.utils.find(lambda c: c.name.lower() == clean.lower(), g.categories)
    if not isinstance(cat, discord.CategoryChannel):
        return await ctx.send(embed=error_embed("❌ Catégorie introuvable", "Donne l'ID (clic droit → Copier l'identifiant) ou le nom exact."))
    msg = await ctx.send(embed=info_embed("⏳ Configuration...", f"Création de **{len(LOG_GROUPS)}** salons dans **{cat.name}**."))
    db_exec("INSERT OR REPLACE INTO log_category VALUES (?, ?, ?, ?)", (str(g.id), str(cat.id), str(ctx.author.id), now_ts()))
    clear_action_channels(g.id)
    ows = {
        g.default_role: discord.PermissionOverwrite(view_channel=False),
        g.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, embed_links=True, read_message_history=True),
    }
    created, errors = 0, []
    for name, (topic, actions) in LOG_GROUPS.items():
        try:
            ch = await g.create_text_channel(name=name, category=cat, overwrites=ows, topic=f"Antifast : {topic}",
                                             reason=f"Antifast categorie par {ctx.author}")
            for a in actions:
                set_action_channel(g.id, a, ch.id)
            created += 1
            await asyncio.sleep(0.5)
        except discord.HTTPException as e:
            errors.append(f"{name} : {type(e).__name__}")
    em = success_embed("✅ Catégorie configurée",
                       f"**Catégorie :** {cat.mention}\n**Salons créés :** {created}/{len(LOG_GROUPS)}\n\n"
                       f"*Salons visibles uniquement par le bot : donne l'accès aux rôles staff que tu veux.*")
    if errors:
        em.add_field(name="Erreurs", value="\n".join(errors), inline=False)
    await msg.edit(embed=em)
    await internal_log(g, "Catégorie de logs configurée", ctx.author, f"{cat.mention} : {created} salons")


@bot.command(name="uncategorie", aliases=["uncategory"])
async def _uncategorie(ctx, option: str = None):
    if not await gate(ctx, 4):
        return
    g = ctx.guild
    if not db_one("SELECT 1 FROM log_category WHERE guild_id = ?", (str(g.id),)):
        return await ctx.send(embed=error_embed("Aucune catégorie", "Pas de catégorie de logs configurée."))
    deleted = 0
    if option and option.lower() in ("delete", "suppr"):
        for cid in set(get_action_channels(g.id).values()):
            ch = g.get_channel(int(cid))
            if ch:
                try:
                    await ch.delete(reason=f"Antifast uncategorie par {ctx.author}")
                    deleted += 1
                    await asyncio.sleep(0.4)
                except discord.HTTPException:
                    pass
    db_exec("DELETE FROM log_category WHERE guild_id = ?", (str(g.id),))
    clear_action_channels(g.id)
    await ctx.send(embed=success_embed("✅ Catégorie retirée",
                                       f"Mapping supprimé." + (f"\n**{deleted}** salon(s) supprimé(s)." if deleted else "\n*Salons conservés.*")))


def build_emoji_embed(guild=None):
    emojis = get_emojis()
    em = discord.Embed(title="🎨 Emojis personnalisables",
                       description="Choisis un emoji à modifier dans le menu déroulant.\n"
                                   "Tu peux mettre un emoji classique (🔥) ou un emoji du serveur (<:nom:id>).",
                       color=embed_color())
    em.add_field(name="🎙️ Help", value="\n".join(f"{emojis[k]} **{EMOJI_LABELS[k]}**" for k in DEFAULT_EMOJIS if k.startswith("help_")), inline=False)
    em.add_field(name="🛡️ Panneau", value="\n".join(f"{emojis[k]} **{EMOJI_LABELS[k]}**" for k in DEFAULT_EMOJIS if not k.startswith("help_")), inline=False)
    apply_thumbnail(em, guild)
    return em


class EmojiSelect(discord.ui.Select):
    def __init__(self):
        options = [discord.SelectOption(label=EMOJI_LABELS[k][:100], value=k, emoji=_emoji_for_select(get_emoji(k)),
                                        description=k[:100]) for k in DEFAULT_EMOJIS]
        super().__init__(placeholder="Choisis un emoji à modifier...", min_values=1, max_values=1, options=options)

    async def callback(self, interaction: discord.Interaction):
        key = self.values[0]
        panel_msg, author_id, guild = interaction.message, self.view.author_id, self.view.guild
        val = await ask_value(interaction, author_id, f"📨 Envoie l'emoji pour **{EMOJI_LABELS[key]}** dans ce salon. *(60 secondes)*")
        if val:
            set_emoji(key, val)
        try:
            view = EmojiView(author_id, guild)
            await panel_msg.edit(embed=build_emoji_embed(guild), view=view)
            view.message = panel_msg
        except discord.HTTPException:
            pass


class EmojiView(OwnedView):
    def __init__(self, author_id, guild=None):
        super().__init__(author_id, guild, min_rank=4)
        self.add_item(EmojiSelect())

    @discord.ui.button(label="Tout réinitialiser", style=discord.ButtonStyle.danger, emoji="♻️", row=1)
    async def reset(self, interaction: discord.Interaction, button: discord.ui.Button):
        reset_emojis()
        view = EmojiView(self.author_id, self.guild)
        await interaction.response.edit_message(embed=build_emoji_embed(self.guild), view=view)
        view.message = interaction.message


@bot.command(name="setemoji")
async def _setemoji(ctx, key: str = None, *, value: str = None):
    if not await gate(ctx, 4):
        return
    if key is not None and value is not None:
        if key not in DEFAULT_EMOJIS:
            return await ctx.send(embed=error_embed("❌ Clé inconnue", "Clés valides :\n" + "\n".join(DEFAULT_EMOJIS)))
        set_emoji(key, value.strip())
        return await ctx.send(embed=success_embed("✅ Emoji modifié", f"{key} → {value.strip()}"))
    view = EmojiView(ctx.author.id, ctx.guild)
    view.message = await ctx.send(embed=build_emoji_embed(ctx.guild), view=view)


# ========================= ERROR HANDLING =========================

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandInvokeError):
        error = error.original
    if isinstance(error, (commands.CommandNotFound, commands.CheckFailure)):
        return
    if isinstance(error, (commands.MemberNotFound, commands.UserNotFound)):
        await ctx.send(embed=error_embed("❌ Utilisateur introuvable", "Impossible de trouver cet utilisateur."))
    elif isinstance(error, commands.ChannelNotFound):
        await ctx.send(embed=error_embed("❌ Salon introuvable", "Impossible de trouver ce salon."))
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=error_embed("❌ Argument manquant", f"Il te manque l'argument : {error.param.name}."))
    elif isinstance(error, commands.BadArgument):
        await ctx.send(embed=error_embed("❌ Argument invalide", str(error)))
    elif isinstance(error, discord.Forbidden):
        await ctx.send(embed=error_embed("❌ Permissions manquantes", "Le bot n'a pas les permissions nécessaires."))
    else:
        log.error(f"Erreur '{ctx.command}' par {ctx.author} : {error}\n"
                  + "".join(traceback.format_exception(type(error), error, error.__traceback__)))
        try:
            await ctx.send(embed=error_embed("❌ Erreur interne", "Une erreur inattendue est survenue. Les logs ont été générés."))
        except discord.HTTPException:
            pass
        if ctx.guild:
            await internal_log(ctx.guild, "Erreur de commande", ctx.author,
                               f"`{ctx.command}` : `{type(error).__name__}: {str(error)[:400]}`", color=0xf04747)


# ========================= RUN =========================
if __name__ == "__main__":
    try:
        log.info("Démarrage du bot Antifast...")
        bot.run(BOT_TOKEN, log_handler=None)
    except KeyboardInterrupt:
        log.info("Arrêt demandé.")
    except Exception as e:
        log.error(f"Erreur fatale : {e}", exc_info=True)
        sys.exit(1)
