# ==============================================================================
#  AURA OSINT HUB - API + Admin Panel
#  Wraps upstream OSINT APIs behind your own key-system + admin panel.
# ==============================================================================
import os
import sys
import json
import re
import time
import sqlite3
import secrets
import csv
import urllib.request
import urllib.parse
import base64
from functools import wraps
from datetime import datetime, timedelta

from flask import (Flask, request, session, redirect, url_for, render_template,
                   Response, flash, get_flashed_messages, jsonify, g)
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if os.environ.get("VERCEL"):
    DATA_DIR = "/tmp/data"
else:
    DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "osint_hub.db")
SECRET_FILE = os.path.join(DATA_DIR, "secret.key")

PORT = int(os.environ.get("PORT", "5005"))
HOST = os.environ.get("HOST", "0.0.0.0")

DEFAULT_DEVELOPER = os.environ.get("DEVELOPER", "@Yourr_aura")
ADMIN_USER = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASSWORD", "aura@9751")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

os.makedirs(DATA_DIR, exist_ok=True)

# ---------------------------------------------------------------- MongoDB Cloud Sync
MONGO_URI = os.environ.get(
    "MONGO_URI",
    "mongodb+srv://benbalu17_db_user:Aura%4097519751@cluster0.tij9h6v.mongodb.net/osint_hub?retryWrites=true&w=majority"
)

_mongo_last_push = 0
_mongo_client_inst = None

def get_mongo_fs():
    global _mongo_client_inst
    if not MONGO_URI:
        return None
    try:
        from pymongo import MongoClient
        import gridfs
        if _mongo_client_inst is None:
            _mongo_client_inst = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        return gridfs.GridFS(_mongo_client_inst.get_database("osint_hub"))
    except Exception as e:
        print("[MONGO CONNECTION ERROR]", e, flush=True)
        return None

def sync_from_mongo():
    try:
        fs = get_mongo_fs()
        if fs and fs.exists({"filename": "osint_hub.db"}):
            fout = fs.get_last_version("osint_hub.db")
            with open(DB_PATH, "wb") as f:
                f.write(fout.read())
            print("[MONGO SYNC] Successfully loaded osint_hub.db from MongoDB Atlas", flush=True)
            return True
        elif os.path.exists(seed_db):
            with open(seed_db, "rb") as f:
                data = f.read()
            with open(DB_PATH, "wb") as f:
                f.write(data)
            if fs:
                fs.put(data, filename="osint_hub.db")
                print("[MONGO SYNC] Uploaded seed osint_hub.db to MongoDB Atlas", flush=True)
            return True
    except Exception as e:
        print("[MONGO SYNC FROM ERROR]", e, flush=True)
    return False

def checkpoint_db():
    try:
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.close()
    except Exception:
        pass

def sync_to_mongo(force=False):
    global _mongo_last_push
    now = time.time()
    if not force and (now - _mongo_last_push < 3):
        return
    try:
        if not os.path.exists(DB_PATH):
            return
        checkpoint_db()
        fs = get_mongo_fs()
        if not fs:
            return
        with open(DB_PATH, "rb") as f:
            data = f.read()
        for old in fs.find({"filename": "osint_hub.db"}):
            try:
                fs.delete(old._id)
            except Exception:
                pass
        fs.put(data, filename="osint_hub.db")
        _mongo_last_push = now
    except Exception as e:
        print("[MONGO SYNC TO ERROR]", e, flush=True)

# Seed DB from Mongo or local
seed_db = os.path.join(BASE_DIR, "data", "osint_hub.db")
sync_from_mongo()

# ---------------------------------------------------------------- session key
app.secret_key = os.environ.get("SECRET_KEY", "aura-osint-hub-permanent-super-secret-key-9751")

# ----------------------------------------------------------------------- db
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")   # fast commits (WAL ke saath safe)
    return conn

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'admin',
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_active INTEGER DEFAULT 1,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS api_keys(
  id INTEGER PRIMARY KEY,
  key TEXT UNIQUE NOT NULL,
  client TEXT DEFAULT '',
  note TEXT DEFAULT '',
  allowed TEXT DEFAULT 'all',            -- 'all' or csv of endpoint slugs
  usage_mode TEXT DEFAULT 'unlimited',   -- unlimited | rate_limited | fixed_cap
  daily_limit INTEGER DEFAULT 0,         -- 0 = unlimited
  per_min_limit INTEGER DEFAULT 0,       -- 0 = unlimited
  total_cap INTEGER DEFAULT 0,           -- 0 = unlimited (fixed cap mode)
  total_hits INTEGER DEFAULT 0,
  today_hits INTEGER DEFAULT 0,
  today_date TEXT DEFAULT '',
  minute_hits INTEGER DEFAULT 0,
  minute_start INTEGER DEFAULT 0,
  is_active INTEGER DEFAULT 1,
  expires_at TEXT,                       -- ISO date or NULL for lifetime
  style_developer TEXT DEFAULT '',       -- per-key developer override
  style_template TEXT DEFAULT '',        -- per-key JSON template (raw)
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS endpoints(
  id INTEGER PRIMARY KEY,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  emoji TEXT DEFAULT '🔌',
  url_template TEXT NOT NULL,
  upstream_key TEXT DEFAULT '',
  enabled INTEGER DEFAULT 1,
  term_param TEXT DEFAULT 'term',
  sort_order INTEGER DEFAULT 999,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS logs(
  id INTEGER PRIMARY KEY,
  key_id INTEGER,
  key_string TEXT,
  endpoint TEXT,
  term TEXT,
  status_code INTEGER,
  success INTEGER,
  response_time REAL,
  message TEXT DEFAULT '',
  response_preview TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts(
  id INTEGER PRIMARY KEY,
  username TEXT,
  role TEXT DEFAULT 'unknown',
  ip TEXT DEFAULT '',
  status TEXT,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS settings(
  k TEXT PRIMARY KEY,
  v TEXT
);
CREATE TABLE IF NOT EXISTS cache(
  slug TEXT NOT NULL,
  term TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT,
  PRIMARY KEY(slug, term)
);
"""

def init_db():
    conn = db()
    conn.executescript(SCHEMA)
    # seed endpoints
    if conn.execute("SELECT COUNT(*) c FROM endpoints").fetchone()["c"] == 0:
        rows = [
            ("num",    "Number Info",       "📱", "http://uersxinfo.in/api?key={upstream_key}&type=mobile&term={term}",
             "numcudt", "term", 1),
            ("tg",     "TG to Number",      "📞", "https://jgvicvhgfwcfndgookul.supabase.co/functions/v1/bot-api?key={upstream_key}&tool=telegramtonumber&term={term}",
             "CODERPETRO", "term", 2),
            ("numpak", "Pakistan Number",   "🇵🇰", "http://wasifali.biz.id/public_apis/sim-info-api.php?search={term}",
             "", "", 3),
            ("osint",  "OSINT Search",      "🔎", "https://l34k-osint.onrender.com/search?key={upstream_key}&query={term}",
             "028d9205ebab1366bd43d8835e1f7cf9", "term", 4),
            ("aadhr",  "Aadhaar Info",      "🆔", "https://sahilxher.madewith.me/api/aadhr?key={upstream_key}&q={term}",
             "FELIX69", "aadhar", 6),
            ("pincode", "Pincode Search",   "📮", "https://myspeedpost.com/pincode-search?q={term}",
             "", "pincode", 7),
            ("ifsc",    "IFSC Info",        "🏦", "https://ifsc.razorpay.com/{term}",
             "", "ifsc", 8),
            ("insta",   "Instagram Info",   "📸", "https://sahilxher.madewith.me/api/insta?key={upstream_key}&q={term}",
             "FELIX69", "username", 9),
            ("snap",    "Snapchat Info",    "👻", "https://www.snapchat.com/add/{term}",
             "", "username", 10),
            ("domain",  "Domain Info",      "🔗", "https://rdap.org/domain/{term}",
             "", "domain", 11),
            ("leak",    "Leak OSINT",       "🔍", "https://nmdllpezcocquamhgpmb.supabase.co/functions/v1/lookup?number={term}",
             "", "number", 13),
        ]
        for i, (slug, name, emoji, tpl, ekey, tp, srt) in enumerate(rows):
            conn.execute(
                "INSERT OR IGNORE INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)", (slug, name, emoji, tpl, ekey, tp, srt, now_iso()))
    # migration: image endpoint (OpenRouter Image API — Qwen Image 2.1 Turbo default)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='image'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("image", "AI Image Generator", "🎨",
             "https://openrouter.ai/api/v1/images",
             "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",
             "prompt", 14, now_iso()))
    # migration: osint endpoint ka brand name — "OSINT Leak Pro"
    conn.execute("UPDATE endpoints SET name='OSINT Leak Pro' WHERE slug='osint' AND name!='OSINT Leak Pro'")
    # migration: ff endpoint (user khud banai Free Fire info API — Vercel pe hosted, keyless)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='ff'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("ff", "Free Fire Info", "🎮",
             "https://infoextracted.vercel.app/accinfo?uid={term}",
             "", "uid", 17, now_iso()))
    # migration: upi endpoint (Airtel paydigi unauth VPA verify — keyless)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='upi'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("upi", "UPI Info", "💸",
             "https://paydigi.airtel.in/web/pg-service/v1/validate/vpa/{term}",
             "", "vpa", 16, now_iso()))
    # migration: imei endpoint (local TAC database — MoazEb/tac-database, keyless)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='imei'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("imei", "IMEI Info", "📲",
             "", "", "imei", 15, now_iso()))
    # migration: tg endpoint -> {param} placeholder (auto username/userid)
    conn.execute(
        "UPDATE endpoints SET url_template='https://tele-to-phone.felixrdx.xyz/api/developer/Cyb3rB4nn3r/fast?key={upstream_key}&{param}={term}', "
        "term_param='username' WHERE slug='tg' AND url_template LIKE '%username={term}%'")
    # migration: tg upstream (tele-to-phone.felixrdx.xyz)
    conn.execute(
        "UPDATE endpoints SET url_template='https://tele-to-phone.felixrdx.xyz/api/developer/Cyb3rB4nn3r/fast?key={upstream_key}&{param}={term}', "
        "upstream_key='6051223b2f1c424bbf9257b371506d52', term_param='username', enabled=1 "
        "WHERE slug='tg'")
    conn.execute("DELETE FROM cache WHERE slug='tg'")
    # migration: ip endpoint (ip-api.com) — purane DB me bhi add ho jaye
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='ip'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("ip", "IP Info", "🌐",
             "http://ip-api.com/json/{term}?fields=status,message,continent,continentCode,country,countryCode,"
             "region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,"
             "reverse,mobile,proxy,hosting,query",
             "", "ip", 5, now_iso()))
    # migration: osint upstream naye Deep OSINT developer API pe shift
    conn.execute(
        "UPDATE endpoints SET url_template='https://deeposint.felixrdx.xyz/api/developer/Cyb3rB4nn3r/?key={upstream_key}&query={term}' "
        "WHERE slug='osint' AND url_template NOT LIKE '%api/developer/Cyb3rB4nn3r/%'")
    # migration: osint upstream key naya (purana naye server pe invalid hai)
    conn.execute(
        "UPDATE endpoints SET upstream_key='3a2a165a22b94bf6657eb8b491a267b2' "
        "WHERE slug='osint' AND (upstream_key='' OR upstream_key IN ('028d9205ebab1366bd43d8835e1f7cf9','numcudt'))")
    # migration: ip endpoint me 'query' field add (response me clean 'ip' field ke liye)
    conn.execute(
        "UPDATE endpoints SET url_template=replace(url_template, 'proxy,hosting', 'proxy,hosting,query') "
        "WHERE slug='ip' AND url_template LIKE '%hosting' AND url_template NOT LIKE '%query'")
    # migration: leak endpoint (supabase leak-DB lookup — keyless upstream)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='leak'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("leak", "Leak OSINT", "🔍",
             "https://nmdllpezcocquamhgpmb.supabase.co/functions/v1/lookup?number={term}",
             "", "number", 13, now_iso()))
    # migration: aadhr endpoint (Aadhaar -> SIM records) — purane DB me bhi add ho jaye
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='aadhr'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("aadhr", "Aadhaar Info", "🆔",
             "https://sahilxher.madewith.me/api/aadhr?key={upstream_key}&q={term}",
             "FELIX69", "aadhar", 6, now_iso()))
    # migration: pincode endpoint (myspeedpost Livewire page scraper) — purane DB me bhi add ho jaye
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='pincode'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("pincode", "Pincode Search", "📮",
             "https://myspeedpost.com/pincode-search?q={term}",
             "", "pincode", 7, now_iso()))
    # migration: ifsc endpoint (razorpay fast API, in-app enrichment ke saath)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='ifsc'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("ifsc", "IFSC Info", "🏦",
             "https://ifsc.razorpay.com/{term}",
             "", "ifsc", 8, now_iso()))
    # migration: insta endpoint (sahilxher instagram info)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='insta'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("insta", "Instagram Info", "📸",
             "https://sahilxher.madewith.me/api/insta?key={upstream_key}&q={term}",
             "FELIX69", "username", 9, now_iso()))
    # migration: snap endpoint (hamara apna snapchat scraper — zero upstream)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='snap'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("snap", "Snapchat Info", "👻",
             "https://www.snapchat.com/add/{term}",
             "", "username", 10, now_iso()))
    # migration: domain endpoint (RDAP + DNS + IP + HTTP — sab hamara apna, no upstream)
    if not conn.execute("SELECT 1 x FROM endpoints WHERE slug='domain'").fetchone():
        conn.execute(
            "INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("domain", "Domain Info", "🔗",
             "https://rdap.org/domain/{term}",
             "", "domain", 11, now_iso()))
    # cleanup: vehicle endpoint hata diya (user ki demand) — DB se bhi saaf
    conn.execute("DELETE FROM endpoints WHERE slug='vehicle'")
    conn.execute("DELETE FROM cache WHERE slug='vehicle'")
    # cleanup: gag endpoint hata diya (user ki demand) — DB se bhi saaf
    conn.execute("DELETE FROM endpoints WHERE slug='gag'")
    conn.execute("DELETE FROM cache WHERE slug='gag'")
    # seed demo key
    if conn.execute("SELECT COUNT(*) c FROM api_keys").fetchone()["c"] == 0:
        conn.execute(
            "INSERT INTO api_keys(key,client,note,allowed,usage_mode,is_active,created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            ("DEMO123", "Demo", "Auto-seeded demo key — delete it after testing",
             "all", "unlimited", 1, now_iso()))
    # default admin
    if conn.execute("SELECT COUNT(*) c FROM admins").fetchone()["c"] == 0:
        u = ADMIN_USER
        p = ADMIN_PASS
        conn.execute("INSERT INTO admins(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                     (u, generate_password_hash(p), "head admin", now_iso()))
        print(f"[BOOT] Admin created -> username: {u}  password: {p}  (change it in Settings)", flush=True)
    conn.commit()
    conn.close()

def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def today_str():
    return datetime.now().strftime("%Y-%m-%d")

# ----------------------------------------------------------------- settings
# in-memory settings cache (60s) — har request pe DB conn bachao
_SETTINGS_MEM = {}
_SETTINGS_MEM_TTL = 60

def set_setting(k, v):
    conn = db()
    conn.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
    conn.commit(); conn.close()
    _SETTINGS_MEM[k] = (v, time.time())

def get_setting(k, d=""):
    hit = _SETTINGS_MEM.get(k)
    if hit:
        val, ts = hit
        if time.time() - ts < _SETTINGS_MEM_TTL:
            return val
    conn = db()
    row = conn.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    conn.close()
    if row:
        _SETTINGS_MEM[k] = (row["v"], time.time())
        return row["v"]
    return d

# ------------------------------------------------------------ L1 memo cache
# in-process response cache (15 min, max 400) — DB cache iska L2 hai
_MEMCACHE = {}
_MEMCACHE_TTL = 900
_MEMCACHE_MAX = 400

def memcache_get(k):
    v = _MEMCACHE.get(k)
    if not v:
        return None
    payload, ts = v
    if time.time() - ts > _MEMCACHE_TTL:
        _MEMCACHE.pop(k, None)
        return None
    return payload

def memcache_put(k, payload):
    try:
        if len(_MEMCACHE) >= _MEMCACHE_MAX:
            _MEMCACHE.pop(next(iter(_MEMCACHE)))
        _MEMCACHE[k] = (payload, time.time())
    except Exception:
        pass

def developer_name():
    d = get_setting("developer", DEFAULT_DEVELOPER)
    if not d or d == "@auraxinfo":
        return DEFAULT_DEVELOPER
    return d

# -------------------------------------------------------------------- cache
def cache_ttl_minutes():
    """default 720 min (12h). 0 = cache off. Settings table me 'cache_ttl' key se control karo."""
    try:
        return int(get_setting("cache_ttl", "720") or 0)
    except Exception:
        return 720

def cache_get(slug, term):
    conn = db()
    row = conn.execute("SELECT payload, created_at FROM cache WHERE slug=? AND term=?",
                       (slug, term)).fetchone()
    conn.close()
    if not row:
        return None
    try:
        t = datetime.strptime(str(row["created_at"])[:19], "%Y-%m-%d %H:%M:%S")
        if datetime.now() - t <= timedelta(minutes=cache_ttl_minutes()):
            return json.loads(row["payload"])
    except Exception:
        pass
    return None

def cache_put(slug, term, payload):
    try:
        conn = db()
        conn.execute(
            "INSERT INTO cache(slug,term,payload,created_at) VALUES(?,?,?,?) "
            "ON CONFLICT(slug,term) DO UPDATE SET payload=excluded.payload, created_at=excluded.created_at",
            (slug, term, json.dumps(payload, ensure_ascii=False), now_iso()))
        conn.commit(); conn.close()
    except Exception:
        pass

def upstream_error_text(payload):
    """Upstream apna error bhejta hai ({status:false, error:{code,title,message}}) -> readable text, warna None."""
    if not isinstance(payload, dict):
        return None
    err = payload.get("error")
    if payload.get("status") is False and isinstance(err, dict):
        title = (err.get("title") or "").strip()
        msg = (err.get("message") or "").strip()
        txt = (title + (" — " + msg if msg else "")).strip()
        code = (err.get("code") or err.get("CODE") or "").upper()
        if "KEY" in code or "KEY" in txt.upper():
            txt += " (upstream key invalid/expired — Admin > Endpoints me naya key dalo)"
        return txt or "upstream rejected the request"
    if payload.get("status") is False and isinstance(err, str):
        # insta jaise wrapper: {status:false, error:"API Not Responding", message:"..."}
        msg = (payload.get("message") or "").strip()
        txt = (err.strip() + (" — " + msg if msg else "")).strip()
        return txt or "upstream rejected the request"
    return None

# ------------------------------------------------------------------- pincode
# myspeedpost.com pincode-search Ek Livewire page hai — office records HTML ke
# andar `return this.chunk([{key,label,value},...], cardCount);` chunks ki tarah embedded
PINCODE_CHUNK_RE = re.compile(r"return this\.chunk\((\[.*?\])\s*,\s*cardCount\)", re.S)

def parse_pincode_html(raw):
    """Livewire chunks ko unescape karke records list banata hai (dedup ke saath)."""
    records, seen = [], set()
    for chunk in PINCODE_CHUNK_RE.findall(raw or ""):
        txt = (chunk.replace("&quot;", '"').replace("&#039;", "'")
                    .replace("&amp;", "&"))
        try:
            arr = json.loads(txt)
        except Exception:
            continue
        if not isinstance(arr, list):
            continue
        rec = {p.get("key"): p.get("value") for p in arr
               if isinstance(p, dict) and p.get("key")}
        if not rec:
            continue
        sig = json.dumps(rec, sort_keys=True)
        if sig in seen:
            continue
        seen.add(sig)
        records.append(rec)
    return records

def pincode_payload(term, records):
    """Hamare style ka clean payload: {pincode, total, records} label-based keys hata ke."""
    clean = []
    for r in records:
        # label fields unka kaam hai; sirf value fields rakho
        rec = {k: v for k, v in r.items() if k not in ("label",)}
        clean.append(rec)
    return {"pincode": term, "total": len(clean), "records": clean}

# --------------------------------------------------------------- bank meta
# major Indian banks ki static meta (IFSC endpoint ka "bank" block build karne ke liye)
BANK_META = {
    "SBIN": {"name": "State Bank of India", "category": "Public Sector", "hq": "Mumbai", "founded": 1955, "tagline": "The Banker to Every Indian", "swift": "SBININBB", "upi": "sbi"},
    "HDFC": {"name": "HDFC Bank", "category": "Private Sector", "hq": "Mumbai", "founded": 1994, "tagline": "We Understand Your World", "swift": "HDFCINBB", "upi": "hdfcbank"},
    "ICIC": {"name": "ICICI Bank", "category": "Private Sector", "hq": "Mumbai", "founded": 1995, "tagline": "Khayal Apka", "swift": "ICICINBB", "upi": "icici"},
    "UTIB": {"name": "Axis Bank", "category": "Private Sector", "hq": "Mumbai", "founded": 1993, "tagline": "Badhti Ka Naam Zindagi", "swift": "AXISINBB", "upi": "axisbank"},
    "KKBK": {"name": "Kotak Mahindra Bank", "category": "Private Sector", "hq": "Mumbai", "founded": 2003, "tagline": "Ko Badalna Hi Raat Kaam Ho", "swift": "KKBKINBB", "upi": "kotak"},
    "PUNB": {"name": "Punjab National Bank", "category": "Public Sector", "hq": "New Delhi", "founded": 1894, "tagline": "The Name You Can Bank Upon", "swift": "PUNBINBB", "upi": "pnb"},
    "BARB": {"name": "Bank of Baroda", "category": "Public Sector", "hq": "Vadodara", "founded": 1908, "tagline": "India's International Bank", "swift": "BARBINBB", "upi": "bankofbaroda"},
    "CBIN": {"name": "Central Bank of India", "category": "Public Sector", "hq": "Mumbai", "founded": 1911, "tagline": "Central To You Since 1911", "swift": "CBININBB", "upi": "centralbank"},
    "CNRB": {"name": "Canara Bank", "category": "Public Sector", "hq": "Bengaluru", "founded": 1906, "tagline": "It's Easy To Change For Those Who You Love", "swift": "CNRBINBB", "upi": "canarabank"},
    "UBIN": {"name": "Union Bank of India", "category": "Public Sector", "hq": "Mumbai", "founded": 1919, "tagline": "Good People To Bank With", "swift": "UBININBB", "upi": "unionbankofindia"},
    "IDIB": {"name": "Indian Bank", "category": "Public Sector", "hq": "Chennai", "founded": 1907, "tagline": "Easiest & Happiest Bank", "swift": "IDIBINBB", "upi": "indianbank"},
    "IOBA": {"name": "Indian Overseas Bank", "category": "Public Sector", "hq": "Chennai", "founded": 1937, "tagline": "Good People To Grow With", "swift": "IOBAINBB", "upi": "indianoverseasbank"},
    "BKID": {"name": "Bank of India", "category": "Public Sector", "hq": "Mumbai", "founded": 1906, "tagline": "Relationship Beyond Banking", "swift": "BKIDINBB", "upi": "bankofindia"},
    "MAHB": {"name": "Bank of Maharashtra", "category": "Public Sector", "hq": "Pune", "founded": 1935, "tagline": "One Family One Bank", "swift": "MAHBINBB", "upi": "mahabank"},
    "UCBA": {"name": "UCO Bank", "category": "Public Sector", "hq": "Kolkata", "founded": 1943, "tagline": "Honours Your Trust", "swift": "UCBAINBB", "upi": "ucobank"},
    "INDB": {"name": "IndusInd Bank", "category": "Private Sector", "hq": "Pune", "founded": 1994, "tagline": "We Make Money Simple", "swift": "INDBINBB", "upi": "indusind"},
    "YESB": {"name": "Yes Bank", "category": "Private Sector", "hq": "Mumbai", "founded": 2004, "tagline": "Experience Our Expertise", "swift": "YESBINBB", "upi": "yesbank"},
    "RATN": {"name": "RBL Bank", "category": "Private Sector", "hq": "Kolhapur", "founded": 1943, "tagline": "Apno Se Bank", "swift": "RATNINBB", "upi": "rblbank"},
    "BAND": {"name": "Bandhan Bank", "category": "Private Sector", "hq": "Kolkata", "founded": 2015, "tagline": "Aapka Bhala, Sabki Bhalai", "swift": "BANDINBB", "upi": "bandhan"},
    "FEDR": {"name": "Federal Bank", "category": "Private Sector", "hq": "Kochi", "founded": 1931, "tagline": "Your Perfect Banking Partner", "swift": "FEDRICBC", "upi": "Federalbank".lower()},
    "IDFB": {"name": "IDFC First Bank", "category": "Private Sector", "hq": "Mumbai", "founded": 2015, "tagline": "The Bank of Firsts", "swift": "IDFBINBB", "upi": "idfcbank"},
    "TMBL": {"name": "Tamilnad Mercantile Bank", "category": "Private Sector", "hq": "Thoothukudi", "founded": 1921, "tagline": "Banking With A Smile", "swift": "TMBLINBB", "upi": "tmbl"},
    "PJSB": {"name": "Punjab & Sind Bank", "category": "Public Sector", "hq": "New Delhi", "founded": 1908, "tagline": "Where Service Is A Way Of Life", "swift": "PJSBINBB", "upi": "punjabandsindbank"},
    "JAKA": {"name": "Jammu & Kashmir Bank", "category": "Public Sector", "hq": "Srinagar", "founded": 1938, "tagline": "Serving To Empower", "swift": "JAKAINBB", "upi": "jkbank"},
}

DEFAULT_BANK_META = {"category": "Scheduled Commercial Bank", "hq": "India", "founded": "N/A", "tagline": "N/A", "swift": None}

IFSC_RE = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")

def ifsc_validation(ifsc):
    ok4 = ifsc[:4].isalpha()
    ok0 = len(ifsc) > 4 and ifsc[4] == "0"
    ok11 = len(ifsc) == 11
    okd = len(ifsc) == 11 and ifsc[5:].isdigit()
    return {"format_valid": ok4 and ok0 and ok11 and okd, "checksum_valid": True,
            "bank_code_valid": ok4, "length_valid": ok11, "fifth_char_zero": ok0}

def banking_hours():
    return {"weekdays": "10:00 AM - 4:00 PM",
            "saturday": "10:00 AM - 1:00 PM (Except 2nd & 4th Saturday)",
            "sunday": "Closed", "lunch": "1:00 PM - 1:30 PM"}

def pincode_records_cached(pin):
    """IFSC location block ke liye post-office records (pehle apna hi pincode cache)."""
    cached = cache_get("pincode", pin)
    if cached is not None and isinstance(cached, dict):
        return cached.get("records") or []
    ep = get_endpoint("pincode")
    if not ep:
        return []
    payload, _dt, _err = fetch_upstream(ep, pin)
    if isinstance(payload, dict):
        recs = payload.get("records") or []
        if recs and cache_ttl_minutes() > 0:
            cache_put("pincode", pin, payload)
        return recs
    return []

def enrich_ifsc(rp, term):
    """Razorpay fast JSON ko user ke enriched format me badlo (bank/branch/codes/services/regulatory/
    metadata/location(nearby post offices)/validation/banking_hours)."""
    ifsc = (rp.get("IFSC") or term or "").upper()
    bank_code, branch_code = ifsc[:4], ifsc[5:]   # 5th char '0' separator hai, branch = last 6
    meta = BANK_META.get(bank_code, DEFAULT_BANK_META)
    addr = rp.get("ADDRESS") or ""
    contact = (rp.get("CONTACT") or "N/A").strip() or "N/A"
    m = re.search(r"(?<!\d)(\d{6})(?!\d)", addr)
    pin = m.group(1) if m else ""

    records = pincode_records_cached(pin) if pin else []
    location = {"pincode": pin or "N/A"}
    if records:
        first = records[0]
        location = {
            "pincode": pin,
            "post_office": first.get("office_name", "N/A"),
            "branch_type": first.get("office_type") or "Branch Post Office",
            "delivery_status": "N/A",
            "division": first.get("division_name", "N/A"),
            "region": first.get("region_name", "N/A"),
            "circle": first.get("circle_name", "N/A"),
            "taluk": "N/A",
            "district": first.get("district_name", "N/A"),
            "state": first.get("state_name", "N/A"),
            "country": "India",
            "nearby_post_offices": [
                {"name": r.get("office_name", "N/A"),
                 "type": r.get("office_type") or "Sub Post Office"}
                for r in records[1:5]
            ],
        }

    return {
        "ifsc": ifsc,
        "bank_code": bank_code,
        "branch_code": branch_code,
        "bank": {
            "name": meta.get("name") or rp.get("BANK") or bank_code,
            "category": meta.get("category", "N/A"),
            "headquarters": meta.get("hq", "N/A"),
            "founded": meta.get("founded", "N/A"),
            "tagline": meta.get("tagline", "N/A"),
            "swift_code": rp.get("SWIFT") or meta.get("swift") or "N/A",
            "status": "Active",
            "global_presence": "India",
        },
        "branch": {
            "name": rp.get("BRANCH") or "N/A",
            "full_address": addr or "N/A",
            "city": rp.get("CITY") or "N/A",
            "district": rp.get("DISTRICT") or "N/A",
            "state": rp.get("STATE") or "N/A",
            "contact_numbers": [contact],
            "email": "N/A",
            "std_code": "N/A",
            "pincode": pin or "N/A",
        },
        "codes": {
            "ifsc": ifsc,
            "micr": rp.get("MICR") or "N/A",
            "swift": rp.get("SWIFT") or meta.get("swift") or "N/A",
            "upi_id": (ifsc.lower() + "@" + (meta.get("upi") or bank_code.lower())),
            "iso_code": "IN",
            "currency": "INR",
        },
        "services": {
            "rtgs": bool(rp.get("RTGS")), "neft": bool(rp.get("NEFT")),
            "imps": bool(rp.get("IMPS")), "upi": bool(rp.get("UPI")),
            "net_banking": True, "mobile_banking": True,
            "sms_banking": True, "cheque_truncation": True,
        },
        "regulatory": {
            "regulated_by": "Reserve Bank of India",
            "rbi_license": "Active",
            "dp_id": rp.get("BANKCODE") == "SBIN" and "IN300206" or "N/A",
            "clearing_member": True,
        },
        "metadata": {
            "timezone": "Asia/Kolkata",
            "last_updated": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "data_source": "RBI - Razorpay IFSC API",
            "query_timestamp": int(time.time() * 1000),
        },
        "location": location,
        "validation": ifsc_validation(ifsc),
        "banking_hours": banking_hours(),
    }

# --------------------------------------------------------------- insta fallback
_IG_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
_IG_SUFFIX = {"k": 1_000, "m": 1_000_000}

def ig_num(token):
    """686M / 8,620 / 308 jaise tokens ko actual number me badalta hai."""
    t = token.strip().replace(",", "")
    m = re.match(r"^([\d.]+)([kKmM]?)$", t)
    if not m:
        return None
    try:
        v = float(m.group(1))
    except ValueError:
        return None
    suf = _IG_SUFFIX.get(m.group(2).lower(), 1)
    return int(round(v * suf))

def scrape_ig_profile(term):
    """Instagram public profile page ke meta tags se fallback info (sahil-style payload).
    Notes: pk/posts list anonymous disabled hote hain — partial data milta hai."""
    user = term.strip().lstrip("@")
    url = "https://www.instagram.com/" + urllib.parse.quote(user, "") + "/"
    req = urllib.request.Request(url, headers={
        "User-Agent": _IG_UA,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    })
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return None, round((time.time() - t0) * 1000, 1), "upstream HTTP " + str(e.code)
    except Exception as e:
        return None, round((time.time() - t0) * 1000, 1), f"upstream error: {e}"
    dt = round((time.time() - t0) * 1000, 1)

    if raw.lstrip().lower().startswith("<!doctype html><html") and "Sorry, this page isn't available" in raw:
        return None, dt, "profile not found"
    og_desc = re.search(r'<meta property="og:description" content="([^"]*)"', raw)
    og_title = re.search(r'<meta property="og:title" content="([^"]*)"', raw)
    if not og_desc:
        return None, dt, "profile meta unavailable (rate-limited)"
    desc = (og_desc.group(1)).replace("&amp;", "&").replace("&quot;", '"')
    full_name, m1 = "", re.search(r'^(.*?)\s*\(@'+re.escape(user)+r'\)', (og_title.group(1) if og_title else ""))
    if m1:
        full_name = m1.group(1).replace("&quot;", '"').replace("&amp;", "&")
    followers = following = posts = None
    for mm in re.finditer(r"([\d.,]+\s*[kKmM]?)\s*(followers|following|posts)", desc):
        tok, target = mm.group(1), mm.group(2)
        n = ig_num(tok)
        if n is None:
            continue
        if target == "followers" and followers is None: followers = n
        elif target == "following" and following is None: following = n
        elif target == "posts" and posts is None: posts = n
    pic = re.search(r'<meta property="og:image" content="([^"]*)"', raw)
    bio_for_media = re.search(r'<meta name="description"[^>]*content="([^"]*)"', raw)
    biography = desc if (m1 is None and og_desc) else (bio_for_media.group(1) if bio_for_media else desc)
    return ({
        "username": user,
        "full_name": full_name or user,
        "biography": biography.replace("&amp;", "&").replace("&quot;", '"'),
        "follower_count": followers or 0,
        "following_count": following or 0,
        "media_count": posts or 0,
        "followers": followers or 0,
        "following": following or 0,
        "posts_count": posts or 0,
        "is_private": ("This account is private" in raw) or ('"is_private":true' in raw),
        "is_verified": '"is_verified":true' in raw,
        "profile_pic_url": (pic.group(1).replace("&amp;", "&") if pic else ""),
        "bio_links": [],
        "posts": [],
        "fetched_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "hd_profile_pic_url": (pic.group(1).replace("&amp;", "&") if pic else ""),
        "leakdata": [{"name": "Instagram"}],
    }), dt, None

_IG_APP_ID = "936619743392459"  # instagram web app id (public, web_profile_info ke liye)
_SX_DEAD_UNTIL = 0.0            # sahilxher key-expired hua to yaha tak skip
_IG_COOL_UNTIL = 0.0            # IG rate-limit hua to itni der tak IG ko chhedna band

def ig_web_profile(term):
    """Instagram web-profile-info API (no login) -> sabse rich public payload.
    Exact counts, HD pic, bio links, verified/private, recent posts."""
    from urllib.error import HTTPError
    user = term.strip().lstrip("@")
    url = ("https://www.instagram.com/api/v1/users/web_profile_info/?username="
           + urllib.parse.quote(user, ""))
    req = urllib.request.Request(url, headers={
        "User-Agent": _IG_UA,
        "x-ig-app-id": _IG_APP_ID,
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.instagram.com/" + urllib.parse.quote(user, "") + "/",
    })
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            d = json.loads(resp.read().decode("utf-8", "replace"))
    except HTTPError as e:
        if e.code == 404:
            return None, round((time.time() - t0) * 1000, 1), "profile not found"
        return None, round((time.time() - t0) * 1000, 1), "upstream HTTP " + str(e.code)
    except Exception as e:
        return None, round((time.time() - t0) * 1000, 1), "upstream error: " + str(e)[:80]
    dt = round((time.time() - t0) * 1000, 1)
    if isinstance(d, dict) and not d.get("data"):
        msg = (d.get("message") or "").lower()
        if "login_required" in msg or "rate" in msg or "checkpoint" in msg:
            return None, dt, "instagram rate-limited (" + (d.get("message") or "") + ")"
    u = (d or {}).get("data", {}).get("user") if isinstance(d, dict) else None
    if not isinstance(u, dict) or not u.get("username"):
        return None, dt, "profile not found"
    med = (u.get("edge_owner_to_timeline_media") or {})
    posts = []
    for edge in (med.get("edges") or [])[:6]:
        n = edge.get("node", {}) if isinstance(edge, dict) else {}
        cap = ""
        ce = (n.get("edge_media_to_caption") or {}).get("edges") or []
        if ce and isinstance(ce[0], dict):
            cap = (ce[0].get("node", {}) or {}).get("text", "")[:120]
        posts.append({"shortcode": n.get("shortcode"),
                      "image": n.get("display_url"),
                      "caption": cap,
                      "likes": ((n.get("edge_liked_by") or {}).get("count")
                                or (n.get("edge_media_preview_like") or {}).get("count")),
                      "comments": ((n.get("edge_media_to_comment") or {}).get("count"))})
    bio_links = []
    for bl in (u.get("bio_links") or []):
        if isinstance(bl, dict) and bl.get("url"):
            bio_links.append(bl["url"].strip())
    return {
        "pk": str(u.get("id", "")),
        "user_id": str(u.get("id", "")),
        "username": u.get("username", user),
        "full_name": (u.get("full_name") or "").strip() or user,
        "biography": u.get("biography") or "",
        "external_url": u.get("external_url"),
        "category": (u.get("category_name") or u.get("business_category_name")),
        "follower_count": (u.get("edge_followed_by") or {}).get("count", 0),
        "following_count": (u.get("edge_follow") or {}).get("count", 0),
        "media_count": med.get("count", 0),
        "followers": (u.get("edge_followed_by") or {}).get("count", 0),
        "following": (u.get("edge_follow") or {}).get("count", 0),
        "posts_count": med.get("count", 0),
        "is_private": bool(u.get("is_private")),
        "is_verified": bool(u.get("is_verified")),
        "profile_pic_url": u.get("profile_pic_url", ""),
        "hd_profile_pic_url": u.get("profile_pic_url_hd") or u.get("profile_pic_url", ""),
        "bio_links": bio_links,
        "posts": posts,
        "fetched_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "leakdata": [{"name": "Instagram"}],
    }, dt, None

def _is_ig_ratelimit(err, payload=None):
    txt = (err or "") + (json.dumps(payload, ensure_ascii=False)[:200]
                         if isinstance(payload, dict) else "")
    t = txt.lower()
    # IG ke ban codes (429 limit, 401 login-required, 411/403 block) sab = cooldownTrigger
    return ("429" in t or "401" in t or "411" in t or "403" in t
            or "rate-limited" in t or "rate limit" in t
            or "login_required" in t)

def fetch_insta_with_backup(ep, term):
    """Chain: instagram web API -> og-meta scraper -> sahilxher (last resort, key
    expired hone pe 30 min ke liye skip). IG rate-limit pe 5 min cooldown,
    taaki har call IG ko aur pareshan na kare."""
    global _SX_DEAD_UNTIL, _IG_COOL_UNTIL
    t0 = time.time()
    if time.time() >= _IG_COOL_UNTIL:
        # 1) instagram direct web API
        payload, dt, err = ig_web_profile(term)
        if payload is not None:
            payload["data_source"] = "Instagram web API (direct)"
            return payload, dt, None
        spent = round(time.time() - t0, 1)
        # 2) og-meta scraper (web API 429 ho tab bhi try — alag endpoint hota hai)
        fb, fdt, ferr = scrape_ig_profile(term)
        if fb is not None:
            fb["data_source"] = "Instagram og-meta (fallback)"
            return fb, round(spent + fdt, 1), None
        if _is_ig_ratelimit(ferr) or _is_ig_ratelimit(err):
            _IG_COOL_UNTIL = time.time() + 300  # 5 min chup
        spent = round(time.time() - t0, 1)
    else:
        spent = 0.0
        err = ferr = "instagram rate-limited (cooldown)"
    # 3) sahilxher sirf tab jab dead-mark na ho
    if time.time() >= _SX_DEAD_UNTIL:
        payload, dt3, err3 = fetch_upstream(ep, term)
        ok = payload is not None and not (isinstance(payload, dict) and not payload)
        if ok and isinstance(payload, dict) and (
                payload.get("success") is False or payload.get("status") is False):
            ok = False
        if not ok:
            txt = (err3 or "") + (json.dumps(payload, ensure_ascii=False)[:150]
                                  if isinstance(payload, dict) else "")
            if ("403" in txt or "expired" in txt.lower()
                    or "key status" in txt.lower()):
                _SX_DEAD_UNTIL = time.time() + 1800  # 30 min ke liye skip
            # asli user-truth ye thi: IG "not found" ya ratelimit — wahi batao
            return payload, round(spent + dt3, 1), (ferr or err3)
        payload["data_source"] = "sahilxher insta API"
        return payload, round(spent + dt3, 1), None
    return None, spent, (ferr or err or "profile not found")

# ------------------------------------------------------------ snapchat info
def snap_payload_from_html(raw, term):
    """Snapchat public add-page HTML -> user ke sample-style payload.
    og:image EXACT wahi web-capture preview URL hota hai jo unke API me tha."""
    user = term.strip().lstrip("@")
    og_img = re.search(r'<meta[^>]*property="og:image" content="([^"]+)"', raw)
    title_m = re.search(r'<title[^>]*>([^<]*)</title>', raw)
    if not og_img or not title_m:
        return None
    pic = og_img.group(1).replace("&amp;", "&")
    title = (title_m.group(1).replace("&amp;", "&")
             .replace("&quot;", '"').replace("&#039;", "'").replace("&#39;", "'"))
    m = re.match(r'^(.*?)(?:\s*\(@' + re.escape(user) + r'\))?(?:\s*\|.*)?$', title)
    full_name = (m.group(1).strip() if m and m.group(1).strip() else user)
    verified = (bool(re.search(r'"(?:isVerified|verified)"\s*:\s*true', raw))
                or "Verified account" in raw)
    story_m = re.search(r'"(?:storyCount|snap_count)"\s*:\s*(\d+)', raw)
    return {
        "username": user,
        "exists": True,
        "description": f"{full_name} is on Snapchat! (@{user})",
        "has_stories": bool(story_m),  # public page pe public stories ka data hi nahi hota
        "story_count": int(story_m.group(1)) if story_m else 0,
        "is_verified": verified,
        "profile_completeness_score": 50,
        "profile_picture_url": pic,
        "profile_picture_info": {
            "direct_url": pic,
            "formats": ["PNG", "JPEG", "WEBP"],
            "opens_in_browser": True,
            "preview_url": pic,
        },
        "profile_url": "https://www.snapchat.com/add/" + user,
        "snapcode_url": ("https://app.snapchat.com/web/deeplink/snapcode?username="
                         + user + "&type=PNG"),
        "full_name": full_name,
    }

# -------------------------------------------------------------- domain info
_DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query?name={n}&type={t}",
    "https://dns.google/resolve?name={n}&type={t}",
)

def _doh_query(name, rtype):
    """DoH (Cloudflare -> Google fallback) se DNS record JSON."""
    import urllib.error as _ue
    for tpl in _DOH_ENDPOINTS:
        try:
            req = urllib.request.Request(
                tpl.format(n=urllib.parse.quote(name.strip(".")), t=rtype),
                headers={"Accept": "application/dns-json",
                         "User-Agent": "AuraOSINT-Hub/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            continue
    return None

def _doh_answer(name, rtype):
    d = _doh_query(name, rtype)
    if not d or d.get("Status") != 0:
        return None, (d or {}).get("Status")
    data = [a.get("data", "").strip().strip('"') for a in d.get("Answer", [])
            if a.get("data")]
    return data, 0

def _rdap_lookup(base):
    req = urllib.request.Request(
        "https://rdap.org/domain/" + base,
        headers={"Accept": "application/rdap+json",
                 "User-Agent": "AuraOSINT-Hub/1.0"})
    with urllib.request.urlopen(req, timeout=12) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))

def _rdap_entity_name(d, role):
    for ent in d.get("entities", []):
        if role in (ent.get("roles") or []):
            v = ent.get("vcardArray")
            for item in (v[1] if v and len(v) > 1 else []):
                if item and item[0] == "fn":
                    return item[3]
            for ent2 in ent.get("entities", []):
                if "abuse" in (ent2.get("roles") or []):
                    va = ent2.get("vcardArray")
                    for item in (va[1] if va and len(va) > 1 else []):
                        if item[0] in ("email", "tel"):
                            return str(item[3])
    return None

def _http_probe(host):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                scheme + "://" + host + "/", headers={
                    "User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)",
                    "Accept-Language": "en-US,en;q=0.9"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return {"status": r.status,
                        "server": r.headers.get("Server"),
                        "ssl": scheme == "https",
                        "final_url": r.geturl()[:200]}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "ssl": scheme == "https"}
        except Exception:
            continue
    return None

def _ip_extra(ip):
    try:
        fields = ("status,country,countryCode,regionName,city,isp,org,as,asname,"
                  "mobile,proxy,hosting")
        with urllib.request.urlopen(
                "http://ip-api.com/json/" + ip + "?fields=" + fields,
                timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None

def domain_lookup(term):
    """Koi bhi website link / domain -> full OSINT payload (RDAP + DNS + IP + HTTP).
    Har module parallel chalta hai, ek fail ho to baaqi chalenge."""
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import urlsplit
    t0 = time.time()
    raw_term = term.strip()
    if not raw_term.startswith(("http://", "https://")):
        raw_term = "https://" + raw_term
    try:
        parts = urlsplit(raw_term)
        host = (parts.netloc or parts.path).split("/")[0].strip().lower()
    except Exception:
        return None, 0.0, "could not parse website link"
    host = host.split(":")[0].split("@")[-1].strip(".")
    if host.startswith("www."):
        host = host[4:]
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2 or not all(re.match(r"^[a-z0-9][a-z0-9\-_]*$", l) for l in labels):
        return None, 0.0, "invalid website address: " + term
    base = ".".join(labels[-2:]) if len(labels) > 2 and labels[-2] not in (
        "co", "com", "org", "net", "gov", "edu") and labels[-1] in (
        "in", "uk", "au", "nz", "za", "br", "jp") else ".".join(labels[-2:])

    jobs = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        jobs["a"] = pool.submit(_doh_answer, host, "A")
        jobs["aaaa"] = pool.submit(_doh_answer, host, "AAAA")
        jobs["mx"] = pool.submit(_doh_answer, host, "MX")
        jobs["txt"] = pool.submit(_doh_answer, host, "TXT")
        jobs["ns"] = pool.submit(_doh_answer, host, "NS")
        jobs["dmarc"] = pool.submit(_doh_answer, "_dmarc." + base, "TXT")
        jobs["rdap"] = pool.submit(_rdap_lookup, base)
        jobs["http"] = pool.submit(_http_probe, host)
        results = {k: (f.result() if not f.exception() else None) for k, f in jobs.items()}

    a, a_st = results["a"]
    aaaa, aaaa_st = results["aaaa"]
    mx, mx_st = results["mx"]
    txt, txt_st = results["txt"]
    ns, ns_st = results["ns"]
    dmarc, dmarc_st = results["dmarc"]
    rdap = results["rdap"]
    http = results["http"]

    if a is None and aaaa is None and a_st == 3:
        return None, round((time.time() - t0) * 1000, 1), "domain does not exist (NXDOMAIN)"

    registrar = abuse = None
    events, status, rdap_ns = [], [], []
    if isinstance(rdap, dict):
        for ev in rdap.get("events", []):
            act = ev.get("eventAction") or ""
            date = (ev.get("eventDate") or "")[:10]
            if act == "registration": events.append(("registered_on", date))
            elif act == "expiration": events.append(("expires_on", date))
            elif act in ("last changed", "last update of RDAP database"): pass
            else: events.append((act.replace(" ", "_"), date))
        registrar = _rdap_entity_name(rdap, "registrar")
        abuse = _rdap_entity_name(rdap, "abuse")
        status = rdap.get("status") or []
        rdap_ns = [n.get("ldhName", "").lower().strip(".")
                   for n in rdap.get("nameservers", []) if n.get("ldhName")]

    spf = any("v=spf1" in t for t in (txt or []))
    dmarc_ok = bool(dmarc)
    who = dict(events) if events else {}

    payload = {
        "domain": host,
        "base_domain": base,
        "registered_on": who.get("registered_on"),
        "updated_on": who.get("last_changed"),
        "expires_on": who.get("expires_on"),
        "registrar": registrar,
        "abuse_contact": abuse,
        "status": status,
        "nameservers": rdap_ns or ns or [],
        "dns": {
            "a": a or [],
            "aaaa": aaaa or [],
            "mx": mx or [],
            "txt": txt or [],
            "ns": ns or [],
        },
        "email_security": {"spf": spf, "dmarc": dmarc_ok},
        "http": http,
    }
    if a:
        geo = _ip_extra(a[0])
        if isinstance(geo, dict) and geo.get("status") == "success":
            payload["hosting"] = {
                "ip": a[0],
                "isp": geo.get("isp"), "org": geo.get("org"),
                "as": geo.get("as"), "country": geo.get("country"),
                "city": geo.get("city"), "mobile": geo.get("mobile"),
                "proxy": geo.get("proxy"), "hosting": geo.get("hosting"),
            }
    return payload, round((time.time() - t0) * 1000, 1), None

# ------------------------------------------------------------------- helpers
def get_endpoint(slug):
    conn = db()
    row = conn.execute("SELECT * FROM endpoints WHERE slug=?", (slug,)).fetchone()
    conn.close()
    return row

def all_endpoints():
    conn = db()
    rows = conn.execute("SELECT * FROM endpoints ORDER BY sort_order, id").fetchall()
    conn.close()
    return rows

def get_key_raw(key):
    if not key:
        return None
    conn = db()
    row = conn.execute("SELECT * FROM api_keys WHERE key=?", (key,)).fetchone()
    conn.close()
    return row

def key_allowed_for(key_row, slug):
    allowed = (key_row["allowed"] or "all").strip()
    if allowed == "all":
        return True
    return slug in [a.strip() for a in allowed.split(",") if a.strip()]

def remaining_days(expires_at):
    if not expires_at:
        return 0, "Lifetime"
    try:
        exp = datetime.strptime(expires_at[:10], "%Y-%m-%d")
        days = (exp.date() - datetime.now().date()).days
        return days, exp.strftime("%Y-%m-%d")
    except Exception:
        return 0, "Lifetime"

def is_expired(key_row):
    if not key_row["expires_at"]:
        return False
    days, _ = remaining_days(key_row["expires_at"])
    return days < 0

def register_hit(key_row):
    """Advance all usage counters; auto-disable key when fixed cap reached."""
    now = datetime.now()
    today = today_str()
    th = key_row["today_hits"] if key_row["today_date"] == today else 0
    epoch = int(time.time())
    ms = key_row["minute_start"] or 0
    mh = key_row["minute_hits"] if (epoch - ms) < 60 else 0
    th += 1
    mh += 1
    capped = False
    conn = db()
    k = conn.execute(
        "UPDATE api_keys SET today_hits=?, today_date=?, minute_hits=?, minute_start=?, total_hits=total_hits+1 "
        "WHERE id=? RETURNING total_hits, total_cap, usage_mode, is_active",
        (th, today, mh, epoch, key_row["id"])).fetchone()
    if (k and k["usage_mode"] == "fixed_cap" and k["total_cap"] > 0
            and k["total_hits"] >= k["total_cap"] and k["is_active"] == 1):
        conn.execute("UPDATE api_keys SET is_active=0 WHERE id=?", (key_row["id"],))
        capped = True
    conn.commit(); conn.close()
    return {"total_hits": k["total_hits"] if k else key_row["total_hits"], "capped": capped}

def add_log(key_row, endpoint, term, status_code, success, rtime, message="", preview=""):
    conn = db()
    conn.execute(
        "INSERT INTO logs(key_id,key_string,endpoint,term,status_code,success,response_time,message,"
        "response_preview,ip,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (key_row["id"] if key_row else None,
         key_row["key"] if key_row else "",
         endpoint, (term or "")[:120], status_code, 1 if success else 0, rtime,
         message[:300], (preview or "")[:600],
         request.headers.get("X-Forwarded-For", request.remote_addr or ""), now_iso()))
    conn.commit(); conn.close()

def log_login_attempt(username, role, status):
    conn = db()
    conn.execute("INSERT INTO login_attempts(username,role,ip,status,created_at) VALUES(?,?,?,?,?)",
                 (username[:60], role, request.headers.get("X-Forwarded-For", request.remote_addr or ""),
                  status, now_iso()))
    conn.commit(); conn.close()

# --------------------------------------------------------------- api output
PLACEHOLDERS = ("__DATA__", "__KEY_DETAILS__", "__DEVELOPER__", "__SUCCESS__",
                "__STATUS_CODE__", "__HTTP_STATUS__", "__ENDPOINT__", "__TERM__")

# country dial codes for auto-detection
DIAL_MAP = {
    "93":"Afghanistan","355":"Albania","213":"Algeria","376":"Andorra","244":"Angola","374":"Armenia",
    "297":"Aruba","61":"Australia","43":"Austria","994":"Azerbaijan","973":"Bahrain","880":"Bangladesh",
    "375":"Belarus","32":"Belgium","501":"Belize","229":"Benin","975":"Bhutan","591":"Bolivia",
    "387":"Bosnia & Herzegovina","267":"Botswana","55":"Brazil","673":"Brunei","359":"Bulgaria",
    "226":"Burkina Faso","257":"Burundi","855":"Cambodia","237":"Cameroon","236":"Central African Rep.",
    "235":"Chad","56":"Chile","86":"China","57":"Colombia","269":"Comoros","242":"Congo","243":"DR Congo",
    "506":"Costa Rica","225":"Cote d'Ivoire","385":"Croatia","53":"Cuba","357":"Cyprus","420":"Czechia",
    "45":"Denmark","253":"Djibouti","593":"Ecuador","20":"Egypt","503":"El Salvador","372":"Estonia",
    "251":"Ethiopia","679":"Fiji","358":"Finland","33":"France","241":"Gabon","220":"Gambia","995":"Georgia",
    "49":"Germany","233":"Ghana","350":"Gibraltar","30":"Greece","502":"Guatemala","224":"Guinea",
    "592":"Guyana","509":"Haiti","504":"Honduras","852":"Hong Kong","36":"Hungary","354":"Iceland",
    "91":"India","62":"Indonesia","98":"Iran","964":"Iraq","353":"Ireland","972":"Israel","39":"Italy",
    "81":"Japan","962":"Jordan","254":"Kenya","965":"Kuwait","996":"Kyrgyzstan","856":"Laos","371":"Latvia",
    "961":"Lebanon","218":"Libya","423":"Liechtenstein","370":"Lithuania","352":"Luxembourg","853":"Macau",
    "389":"North Macedonia","261":"Madagascar","265":"Malawi","60":"Malaysia","960":"Maldives","223":"Mali",
    "356":"Malta","222":"Mauritania","230":"Mauritius","52":"Mexico","373":"Moldova","377":"Monaco",
    "976":"Mongolia","382":"Montenegro","212":"Morocco","258":"Mozambique","95":"Myanmar","264":"Namibia",
    "977":"Nepal","31":"Netherlands","64":"New Zealand","505":"Nicaragua","227":"Niger","234":"Nigeria",
    "850":"North Korea","47":"Norway","968":"Oman","92":"Pakistan","507":"Panama","675":"Papua New Guinea",
    "595":"Paraguay","51":"Peru","63":"Philippines","48":"Poland","351":"Portugal","974":"Qatar",
    "40":"Romania","378":"San Marino","966":"Saudi Arabia","221":"Senegal","381":"Serbia","248":"Seychelles",
    "232":"Sierra Leone","65":"Singapore","421":"Slovakia","386":"Slovenia","252":"Somalia",
    "27":"South Africa","82":"South Korea","34":"Spain","94":"Sri Lanka","249":"Sudan","597":"Suriname",
    "46":"Sweden","41":"Switzerland","963":"Syria","886":"Taiwan","992":"Tajikistan","255":"Tanzania",
    "66":"Thailand","670":"Timor-Leste","228":"Togo","216":"Tunisia","90":"Turkey","993":"Turkmenistan",
    "256":"Uganda","380":"Ukraine","971":"UAE","44":"United Kingdom","598":"Uruguay","58":"Venezuela",
    "84":"Vietnam","681":"Wallis & Futuna","967":"Yemen","260":"Zambia","263":"Zimbabwe",
    "1":"United States/Canada","7":"Russia/Kazakhstan","888":"Telegram Anonymous",
}

COUNTRY_BY_NAME = {v.lower(): (v, "+" + k) for k, v in DIAL_MAP.items()}
COUNTRY_BY_NAME["usa"] = ("United States/Canada", "+1")
COUNTRY_BY_NAME["uk"] = ("United Kingdom", "+44")
COUNTRY_BY_NAME["uae"] = ("UAE", "+971")

def detect_country(ccode, raw_number):
    """Clean detection of country name, country_code dial prefix, and local number.
    Returns (country_name, country_code, local_number).
    NEVER returns '?' or '❓'."""
    raw = (raw_number or "").strip()
    clean_country = (ccode or "").strip()
    for ch in ["❓", "?", "-", "NA", "Unknown"]:
        clean_country = clean_country.replace(ch, "").strip()

    digits = re.sub(r"\D", "", raw)
    if not digits:
        return "Unknown", "-", ""

    country = "Unknown"
    country_code = "-"
    number = digits

    if clean_country.lower() in COUNTRY_BY_NAME:
        country, country_code = COUNTRY_BY_NAME[clean_country.lower()]

    if raw.startswith("+"):
        for L in (4, 3, 2, 1):
            p = digits[:L]
            if p in DIAL_MAP:
                country_code = "+" + p
                country = DIAL_MAP[p]
                if p == "888":
                    number = digits  # Keep full 88805202020 for Telegram Anonymous
                else:
                    number = digits[L:]
                break
    else:
        # Indian mobile numbers: 10 digits starting with 6,7,8,9 (e.g. 6352329758)
        if re.fullmatch(r"[6-9]\d{9}", digits) or (clean_country.lower() == "india" and len(digits) == 10):
            country = "India"
            country_code = "+91"
            number = digits
        elif len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
            country = "India"
            country_code = "+91"
            number = digits[2:]
        elif digits.startswith("888") and len(digits) == 11:
            country = "Telegram Anonymous"
            country_code = "+888"
            number = digits
        elif country != "Unknown" and country_code != "-":
            cc_digs = country_code.lstrip("+")
            if digits.startswith(cc_digs) and len(digits) > len(cc_digs):
                number = digits[len(cc_digs):]
            else:
                number = digits
        else:
            for L in (3, 2, 1):
                p = digits[:L]
                if p in DIAL_MAP and len(digits) >= (L + 6):
                    country = DIAL_MAP[p]
                    country_code = "+" + p
                    number = digits[L:]
                    break

    # Final sanitize to ensure NO '?' or '❓' anywhere
    if any(q in country for q in ("?", "❓")) or not country.strip():
        country = "Unknown"
    if country == "Unknown" and country_code != "-" and country_code.lstrip("+") in DIAL_MAP:
        country = DIAL_MAP[country_code.lstrip("+")]

    return country, country_code, number

TG_FALLBACK_URL = "https://tgosint.vercel.app/?key=drazeX&q="

def tg_fallback_payload(term):
    """tg fallback source (tgosint instance) -> supabase jaisa {success, data} shape,
    ya None (fallback bhi fail hua)."""
    uname = term.strip().lstrip("@")
    try:
        req = urllib.request.Request(
            TG_FALLBACK_URL + urllib.parse.quote("@" + uname),
            headers={"User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)",
                     "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(d, dict) or d.get("error"):
        return None
    ph = d.get("phone_number") or d.get("number") or d.get("phone")
    if isinstance(ph, list):
        if ph and isinstance(ph[0], dict):
            ph = ph[0].get("number")
        elif ph and isinstance(ph[0], str):
            ph = ph[0]
        else:
            ph = None
    if not ph:
        return None
    data = {"phone_number": str(ph)}
    if d.get("telegram_id") or d.get("id"):
        data["telegram_id"] = str(d.get("telegram_id") or d.get("id"))
    if d.get("country"):
        data["country"] = str(d["country"])
    return {"success": True, "data": data}

def normalize_tg(upstream, term, is_cached=False):
    """tg upstream -> user requested response style:
    {result:{country,country_code,msg,number,tg_username,tg_id}, status, cached}"""
    raw_phone = ""
    orig_country = ""
    tg_id = ""
    uname = ""

    if isinstance(upstream, dict):
        tg_id = str(upstream.get("tg_id") or upstream.get("id") or (upstream.get("data") or {}).get("telegram_id") or "").strip()
        uname = str(upstream.get("username") or (upstream.get("data") or {}).get("username") or "").strip().lstrip("@")

        plist = upstream.get("phone")
        if isinstance(plist, list) and len(plist) > 0:
            first_p = plist[0]
            if isinstance(first_p, dict):
                raw_phone = str(first_p.get("number") or "").strip()
                orig_country = str(first_p.get("country") or "").strip()
            elif isinstance(first_p, str):
                raw_phone = str(first_p).strip()
        elif isinstance(plist, str):
            raw_phone = plist.strip()
        elif upstream.get("phone_number"):
            raw_phone = str(upstream.get("phone_number")).strip()
        elif isinstance(upstream.get("data"), dict):
            raw_phone = str(upstream["data"].get("phone_number") or "").strip()
            orig_country = str(upstream["data"].get("country") or "").strip()

    if not tg_id and term.strip().lstrip("@").isdigit():
        tg_id = term.strip().lstrip("@")

    if not uname and not term.strip().lstrip("@").isdigit():
        uname = term.strip().lstrip("@")

    digits = raw_phone.lstrip("+").replace(" ", "").replace("-", "")
    has_found = bool(digits) and digits != "None" and "FAILED" not in str(upstream)

    # Auto detect country, country_code, and clean number
    final_country, final_cc, local_number = detect_country(orig_country, raw_phone)

    is_numeric = term.strip().lstrip("@").isdigit()
    if is_numeric:
        # User ID to Num response style
        res = {
            "country": final_country if has_found else "Unknown",
            "country_code": final_cc if has_found else "-",
            "msg": "Details fetched" if has_found else "Details not found",
            "number": local_number if has_found else "",
            "success": bool(has_found),
        }
    else:
        # Username to Info response style
        res = {
            "country": final_country if has_found else "Unknown",
            "country_code": final_cc if has_found else "-",
            "msg": "Details fetched" if has_found else "Details not found",
            "number": local_number if has_found else "",
            "tg_username": uname or term.strip().lstrip("@"),
            "tg_id": tg_id or "-",
        }

    return {"result": res, "status": has_found, "cached": bool(is_cached)}

CAP_REC = 10  # per-dataset records response me rakhne ki limit (total count honest rehta hai)

LEAK_FALLBACK_URL = "https://nmdllpezcocquamhgpmb.supabase.co/functions/v1/lookup?number="

def leak_fallback_direct(term10):
    """num/osint jaise keyed upstream fail hone pe keyless leak-DB se seedha poochho.
    Returns (payload|None, elapsed_ms)."""
    t0 = time.time()
    try:
        req = urllib.request.Request(
            LEAK_FALLBACK_URL + urllib.parse.quote(term10),
            headers={"User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)",
                     "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_up = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None, 0.0
    out = normalize_leak(raw_up, term10)
    if not isinstance(out, dict) or out.get("total", 0) <= 0:
        return None, round((time.time() - t0) * 1000, 1)
    out["fallback"] = "primary upstream down — keyless leak-DB fallback"
    return out, round((time.time() - t0) * 1000, 1)

def normalize_leak(upstream, term):
    """leak upstream (supabase lookup) -> clean style:
    {query, total, sources:{chain/icmr/rj:{title, description, count, records(capped)}}}"""
    r = upstream if isinstance(upstream, dict) else None
    if isinstance(r, dict) and isinstance(r.get("result"), dict):
        r = r["result"]  # naya supabase lookup double-wrap karta hai (Ankit wrapper ke andar Owner_004)
        if isinstance(r, dict) and isinstance(r.get("result"), dict):
            r = r["result"]
    sources, total = {}, 0
    for key in ("chain", "icmr", "rj"):
        sec = (r or {}).get(key)
        if not isinstance(sec, dict):
            continue
        recs = sec.get("records") or sec.get("results") or []
        if not isinstance(recs, list):
            recs = []
        cnt = sec.get("count") or sec.get("total") or len(recs)
        if not isinstance(cnt, int):
            cnt = len(recs)
        src = {"title": sec.get("title") or key, "description": sec.get("description") or "",
               "count": cnt, "records": recs[:CAP_REC]}
        if len(recs) > CAP_REC:
            src["note"] = f"pehle {CAP_REC} records dikhaye (total {cnt} mila)"
        sources[key] = src
        total += cnt
    return {"query": term, "total": total, "sources": sources, "cached": False}

def normalize_pak(upstream):
    """numpak upstream (sim-info-api) -> clean {count, records} style.
    Upstream ka apna developer/telegram/channel branding hata do —
    envelope me sirf count + records + hamara footer jaye."""
    if not isinstance(upstream, dict):
        return {"count": 0, "records": []}
    records = upstream.get("records")
    if not isinstance(records, list):
        records = upstream.get("data") if isinstance(upstream.get("data"), list) else []
    return {"count": len(records), "records": records}

def reorder_tg(env):
    """key_details ko 'result' ke turant baad rakho (sample style)."""
    if "result" in env and "key_details" in env:
        out = {"result": env["result"], "key_details": env["key_details"]}
        for k, v in env.items():
            if k not in ("result", "key_details"):
                out[k] = v
        return out
    return env

FOOTER_ORDER = ("developer", "success", "status_code", "http_status")

def build_envelope(upstream, key_after, status_code=200, message=""):
    """Wrap upstream payload in our own envelope.
    Order: sab data fields -> key_details -> developer -> success -> status_code -> http_status.
    (Upstream ka apna developer/success/status_code/http_status bhi footer me shift hota hai.)"""
    if isinstance(upstream, dict):
        envelope = {k: v for k, v in upstream.items()
                    if k != "key_details" and k not in FOOTER_ORDER}
    elif upstream is not None:
        envelope = {"data": upstream}
    else:
        envelope = {}
    days, expires_on = remaining_days(key_after["expires_at"])
    envelope["key_details"] = {
        "used_today": key_after["today_hits"] + 1,
        "daily_limit": key_after["daily_limit"] if key_after["daily_limit"] > 0 else 0,
        "valid_days": days if key_after["expires_at"] else 0,
        "expires_on": expires_on,
    }
    envelope["developer"] = key_after["style_developer"] or developer_name()
    envelope["success"] = (200 <= status_code < 300)
    envelope["status_code"] = status_code
    envelope["http_status"] = status_code
    if message:
        envelope["message"] = message
    return envelope

def apply_key_style(envelope, key_row, status_code):
    """Per-key custom response template (raw JSON string with placeholders)."""
    tpl = (key_row["style_template"] or "").strip()
    if not tpl:
        return envelope
    clean = {k: v for k, v in envelope.items()
             if k not in ("key_details", "developer", "success", "status_code", "http_status", "message")}
    data = json.dumps(clean, ensure_ascii=False)
    out = (tpl
           .replace("__DATA__", data)
           .replace("__KEY_DETAILS__", json.dumps(envelope.get("key_details", {}), ensure_ascii=False))
           .replace("__DEVELOPER__", json.dumps(envelope.get("developer", ""), ensure_ascii=False))
           .replace("__SUCCESS__", json.dumps(envelope.get("success", False)))
           .replace("__STATUS_CODE__", str(envelope.get("status_code", status_code)))
           .replace("__HTTP_STATUS__", str(envelope.get("http_status", status_code)))
           .replace("__ENDPOINT__", json.dumps(g.get("api_slug", request.view_args.get("slug", "")), ensure_ascii=False))
           .replace("__TERM__", json.dumps(list(request.args.values())[-1] if request.args else "", ensure_ascii=False)))
    try:
        return json.loads(out)
    except Exception:
        return envelope

def api_error(key_row, slug, code, err, msg=""):
    """Consistent error envelope — keeps developer/@style, no data."""
    if key_row is not None:
        k = dict(key_row)
    else:
        k = {"style_developer": "", "style_template": "", "expires_at": None,
             "today_hits": 0, "daily_limit": 0}
    envelope = {
        "error": err,
        "key_details": None,
        "developer": k.get("style_developer") or developer_name(),
        "success": False,
        "status_code": code,
        "http_status": code,
    }
    if msg:
        envelope["message"] = msg
    if key_row:
        add_log(key_row, slug, first_term(), code, False, 0, err)
    return envelope, code

def json_out(env, code):
    return Response(json.dumps(env, ensure_ascii=False, indent=2),
                    status=code, mimetype="application/json")

# footer keys jo doosre object mein jaate hain (product style)
FOOTER_KEYS = ("key_details", "developer", "success", "status_code", "http_status", "message")

def split_output(env):
    """Product style: pehla object = pure API data, doosra object = key_details/developer/success footer.
    Output literal:  {data...},\n{key_details...}
    NOTE: ye ek concatenated two-object stream hai (valid single JSON nahi) —
    jaise user ke product/consmeers expect karte hain."""
    foot = {k: env[k] for k in FOOTER_KEYS if k in env}
    data = {k: v for k, v in env.items() if k not in foot}
    body = json.dumps(data, ensure_ascii=False, indent=2) + ",\n" + \
           json.dumps(foot, ensure_ascii=False, indent=2)
    return Response(body, status=200 if not isinstance(env.get("status_code"), int) else env.get("status_code", 200),
                    mimetype="application/json")

TERMS = ("term", "search", "query", "username", "userid", "user_id", "uid", "number", "q", "value", "id", "ip", "aadhar", "aadhaar", "pincode", "pin", "ifsc", "insta", "instagram", "snapchat", "domain", "url", "website", "site", "prompt", "prompt_text")
def first_term():
    for t in TERMS:
        v = request.args.get(t, "").strip()
        if v:
            return v
    return ""

def resolve_term_param(ep, term):
    """tg endpoint: numeric IDs ko `userid=` param se bhejo, usernames ko `username=`."""
    if (ep["slug"] or "") == "tg":
        return "userid" if term.isdigit() else "username"
    return ep["term_param"] or "term"

def tg_fetch_url(ep, sterm):
    """tg ke liye seedha URL fetch (bina @ auto-logic ke) — alternate formats try karne ke liye.
    Returns (parsed_json_or_None, elapsed_ms, error_text)."""
    url = (ep["url_template"]
           .replace("{upstream_key}", urllib.parse.quote(ep["upstream_key"] or ""))
           .replace("{param}", resolve_term_param(ep, sterm))
           .replace("{term}", urllib.parse.quote(sterm)))
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)", "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")), \
                round((time.time() - t0) * 1000, 1), None
    except Exception as e:
        return None, round((time.time() - t0) * 1000, 1), f"tg fetch error: {e}"

def fetch_upstream(ep, term):
    """Call upstream URL template, return (parsed_json_or_None, elapsed_ms, error_text)."""
    sterm = term.strip()
    if (ep["slug"] or "") == "tg" and not sterm.lstrip("@").isdigit() and not sterm.startswith("@"):
        sterm = "@" + sterm  # naya supabase upstream ko @username chahiye
    url = (ep["url_template"]
           .replace("{upstream_key}", urllib.parse.quote(ep["upstream_key"] or ""))
           .replace("{param}", resolve_term_param(ep, sterm))
           .replace("{term}", urllib.parse.quote(sterm)))
    headers = {"User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)", "Accept": "application/json",
               "Accept-Language": "en-US,en;q=0.9"}
    req = urllib.request.Request(url, headers=headers)
    t0 = time.time()
    timeout = 20 if ep["slug"] in ("insta", "osint") else 15
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
        dt = round((time.time() - t0) * 1000, 1)
        if ep["slug"] == "snap":
            # snapchat public page HTML -> hamara scraper payload deta hai
            spayload = snap_payload_from_html(raw, term)
            return (spayload, dt, None) if spayload else \
                   (None, dt, "Snapchat profile not found")
        if ep["slug"] == "pincode":
            # pincode page HTML deta hai (Livewire) — chunks parse karke records nikaalo
            recs = parse_pincode_html(raw)
            return (pincode_payload(term, recs), dt, None) if recs else \
                   ({"pincode": term, "total": 0, "records": []}, dt, None)
        try:
            return json.loads(raw), dt, None
        except Exception:
            # upstream ne JSON ki jagah HTML/text bheja (site moved / error page)
            return None, dt, "upstream returned non-JSON response (site changed or down)"
    except urllib.error.HTTPError as e:
        dt = round((time.time() - t0) * 1000, 1)
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        try:
            parsed_body = json.loads(body)
        except Exception:
            parsed_body = None
        uerr = upstream_error_text(parsed_body) if parsed_body is not None else None
        return None, dt, uerr or f"upstream HTTP {e.code}"
    except Exception as e:
        return None, round((time.time() - t0) * 1000, 1), f"upstream error: {e}"

# -------------------------------------------------------- UPI info (Airtel paydigi)
UPI_HANDLE_PSP = {
    "ybl": "PhonePe (Yes Bank)", "ibl": "PhonePe (ICICI)", "yapl": "Yes Bank App",
    "okaxis": "Google Pay (Axis)", "okhdfcbank": "Google Pay (HDFC)", "oksbi": "Google Pay (SBI)",
    "okicici": "Google Pay (ICICI)", "okbizaxis": "Google Pay (Axis Business)",
    "paytm": "Paytm (Paytm Payments Bank)", "paytmwallet": "Paytm Wallet",
    "apl": "Amazon Pay (ICICI)", "upi": "BHIM UPI",
    "waaxis": "Axis Quick Pay", "waicici": "ICICI Quick Pay", "wahdfcbank": "HDFC Quick Pay",
    "wasbi": "SBI Quick Pay", "wapaytm": "Paytm Quick Pay", "axl": "Axis Bank",
    "axis": "Axis Bank", "freecharge": "Freecharge (Axis)", "slice": "slice (SBM)",
    "ikwik": "CRED (IDFC)", "jio": "Jio UPI (Jio Payments Bank)", "fbl": "Fed Bank",
}
UPI_SUFFIX_SWEEP = ["ybl", "okaxis", "okhdfcbank", "oksbi", "paytm", "ibl", "apl",
                    "waaxis", "waicici", "wapaytm", "yapl", "upi", "axl", "freecharge"]

def upi_verify_vpa(vpa, sweep=False):
    """Airtel paydigi unauth UPI verify — (data|None, elapsed_ms, err).
    sweep=True: 429 pe turant skip (sweep fast rehta hai, gunicorn timeout se bachne ke liye)."""
    t0 = time.time()
    ms = lambda: round((time.time() - t0) * 1000, 1)
    headers = {"User-Agent": "Mozilla/5.0 Chrome/101", "Accept": "application/json",
               "channel-id": "WEB_UNAUTH", "Origin": "https://www.airtel.in",
               "Referer": "https://www.airtel.in/"}
    for attempt in range(2):
        req = urllib.request.Request(
            "https://paydigi.airtel.in/web/pg-service/v1/validate/vpa/" + urllib.parse.quote(vpa),
            headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.loads(resp.read().decode("utf-8", "replace")).get("data"), ms(), None
        except urllib.error.HTTPError as e:
            if e.code == 429:
                if sweep:
                    return None, ms(), "rate-limited (429)"
                if attempt == 0:
                    time.sleep(5)  # single verify — zyada saans leke retry
                    continue
                return None, ms(), "upstream rate-limited (429)"
            return None, ms(), f"upi upstream HTTP {e.code}"
        except Exception as e:
            return None, ms(), f"upi upstream error: {e}"
    return None, ms(), "upstream rate-limited (429)"

def upi_lookup(term):
    """VPA (name@handle) -> verify; ya 10-digit mobile -> sabhi PSP handles pe sweep."""
    t0 = time.time()
    ms = lambda: round((time.time() - t0) * 1000, 1)
    vpa = term.strip().lower().replace(" ", "")
    if "@" in vpa:
        if not re.fullmatch(r"[a-z0-9.\-_]{2,64}@[a-z]{2,20}", vpa):
            return None, ms(), "invalid vpa format (use like name@ybl)"
        data, _, err = upi_verify_vpa(vpa)
        if err:
            return None, ms(), err
        if not data or not data.get("vpaValid"):
            return None, ms(), "vpa not valid (no UPI account on this handle)"
        out = {"vpa": data.get("vpa") or vpa, "valid": True,
               "payee_name": data.get("payeeAccountName") or None,
               "psp": UPI_HANDLE_PSP.get(vpa.split("@")[1], "Unknown PSP"),
               "handle": vpa.split("@")[1]}
        return out, ms(), None
    num = re.sub(r"\D", "", vpa)
    if not re.fullmatch(r"[6-9]\d{9}", num):
        return None, ms(), "invalid input (10-digit mobile number ya VPA like name@ybl do)"
    found = []
    limited = 0
    for sfx in UPI_SUFFIX_SWEEP:
        d, _, err = upi_verify_vpa(num + "@" + sfx, sweep=True)
        if d and d.get("vpaValid"):
            name = d.get("payeeAccountName") or None
            found.append({"vpa": num + "@" + sfx, "payee_name": name,
                          "psp": UPI_HANDLE_PSP.get(sfx, "Unknown PSP")})
        elif err and "429" in (err or ""):
            limited += 1
    if not found:
        return None, ms(), "no upi ids found for this number"
    note = "UPI-number alias based verification — payee_name sirf PSP disclose kare to aata hai"
    if limited:
        note += f" ({limited} handles airtel rate-limit ki wajah se skip hue)"
    return {"number": num, "found": len(found), "note": note, "vpas": found}, ms(), None

# -------------------------------------------------------- IMEI info (local TAC db)
TAC_DB = None
TAC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tac_full.csv")

def _load_tac_db():
    """tac_full.csv (MoazEb/tac-database, ~200K devices) ek baar memory me — TAC -> (brand, model)."""
    global TAC_DB
    if TAC_DB is None:
        d = {}
        try:
            with open(TAC_PATH, encoding="utf-8", errors="replace") as f:
                r = csv.reader(f)
                next(r, None)
                for row in r:
                    if len(row) >= 3 and row[1].strip().isdigit():
                        d[row[1].strip()] = (row[0].strip(), row[2].strip())
        except Exception:
            pass
        TAC_DB = d
    return TAC_DB

REPORTING_BODY = {
    "01": "PTCRB (USA)", "02": "PTCRB (USA)", "35": "BABT (UK)", "44": "BABT (UK)",
    "49": "CETECOM ICT (Germany)", "86": "TAF (China)", "91": "TAF (China)",
    "98": "TAF (China)", "99": "JATE (Japan)",
}

def imei_lookup(term):
    """IMEI (15-digit) -> Luhn verify + local TAC database se brand/model. Zero upstream."""
    t0 = time.time()
    ms = lambda: round((time.time() - t0) * 1000, 1)
    imei = re.sub(r"\D", "", term)
    if len(imei) != 15:
        return None, ms(), "invalid imei length (need a 15-digit IMEI)"
    s = 0
    for i, ch in enumerate(reversed(imei[:14])):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    valid = ((10 - s % 10) % 10) == int(imei[14])
    tac = imei[:8]
    rec = _load_tac_db().get(tac)
    if not rec:
        return None, ms(), f"tac {tac} not found in database"
    brand, specs = rec
    model = specs.split(",", 1)[1].strip() if "," in specs else specs.strip()
    out = {"imei": imei, "valid": valid, "check_digit": int(imei[14]),
           "reporting_body": REPORTING_BODY.get(imei[:2]),
           "tac": tac, "brand": brand, "model": model, "full_specs": specs}
    return out, ms(), None

# ------------------------------------------------- AI image generate (OpenRouter)
DEFAULT_IMAGE_MODEL = "qwen/qwen-image-2.1-turbo"
IMG_RESOLUTIONS = ("1K", "2K")

# FLUX.2-klein fallback — OpenRouter pe credits/permission fail ho to free official Spaces
# (token attach karte hi ZeroGPU quota apne account se chalta hai — anonymous quota jaldi khatam hota hai)
FLUX_SPACE_TOKEN = os.environ.get("FLUX_SPACE_TOKEN", "")  # set via Space secret (repo me key NAHI)
IMG_RATIO_DIMS = {"1:1": (1024, 1024), "16:9": (1344, 768), "9:16": (768, 1344),
                  "4:3": (1152, 896), "3:4": (896, 1152), "3:2": (1216, 832), "2:3": (832, 1216)}

FLUX_SPACES = [
    ("https://black-forest-labs-flux-2-klein-4b.hf.space", "infer", "klein",
     "black-forest-labs/FLUX.2-klein-4B"),
    ("https://black-forest-labs-flux-1-schnell.hf.space", "infer", "schnell",
     "black-forest-labs/FLUX.1-schnell"),
    ("https://black-forest-labs-flux-2-klein-9b.hf.space", "generate", "klein",
     "black-forest-labs/FLUX.2-klein-9B"),
]

# NVIDIA NIM — user-key leg (flux-3-image-klein, ~1.8s JSON me b64 JPG deta hai)
NV_IMAGE_KEY = os.environ.get("NV_IMAGE_KEY", "")  # set via Space secret (repo me key NAHI)
NV_IMAGE_URL = "https://ai.api.nvidia.com/v1/genai/black-forest-labs/flux-3-image-klein"
# NVIDIA ke allowed ratios — dono 16:9 / 9:16 wale closest pe map
NV_RATIO_MAP = {"16:9": "13:7", "9:16": "7:13", "1:1": "1:1", "4:3": "4:3",
                "3:4": "3:4", "3:2": "3:2", "2:3": "2:3", "21:9": "21:9"}

def _flux_space_call(host, fn, kind, prompt, w, h):
    """HF Space gradio API se ek image — (out_url, seed, elapsed_ms, err|None).
    Pehle user-token se (ZeroGPU quota), token quota exhaust ('event: error') ho
    jaaye to automatic anonymous (bina token) retry — token band ho to bhi image aaye."""
    t0 = time.time()
    aerr = None
    for auth in (FLUX_SPACE_TOKEN, None):
        out_url, seed, _sdt, aerr = _flux_space_call_auth(host, fn, kind, prompt, w, h, auth)
        if out_url:
            return out_url, seed, round((time.time() - t0) * 1000, 1), None
    return None, None, round((time.time() - t0) * 1000, 1), aerr

def _flux_space_call_auth(host, fn, kind, prompt, w, h, auth):
    """Ek auth mode (token ya anonymous) se generation — (out_url, seed, elapsed_ms, err|None)."""
    t0 = time.time()
    ms = lambda: round((time.time() - t0) * 1000, 1)
    if kind == "schnell":
        data = [prompt[:2000], 0, True, w, h, 4]
    else:
        data = [prompt[:2000], [], "Distilled (4 steps)", 0, True, w, h, 4, 1.0, False]
    hdrs = {"User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)",
            "Content-Type": "application/json"}
    if auth:
        hdrs["Authorization"] = "Bearer " + auth
    req = urllib.request.Request(
        host + "/gradio_api/call/" + fn,
        data=json.dumps({"data": data}).encode("utf-8"),
        headers=hdrs,
        method="POST")
    try:
        ev = json.loads(urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace"))
        eid = ev.get("event_id") or ""
    except Exception as e:
        return None, None, ms(), f"flux-space error: {e}"
    if not eid:
        return None, None, ms(), "flux-space: no event id"
    body = ""
    deadline = time.time() + 60
    while time.time() < deadline:
        time.sleep(2.5)
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                host + "/gradio_api/call/" + fn + "/" + eid,
                headers={"User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)",
                         **({"Authorization": "Bearer " + auth} if auth else {})}),
                timeout=15)
            body = r.read().decode("utf-8", "replace")
            if body:
                break
        except Exception:
            continue
    if not body:
        return None, None, ms(), "flux-space: generation timed out"
    out_url, seed, gerr = None, None, None
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("event: "):
            evname = line[7:].strip()
            if evname == "error":
                gerr = "flux-space: generation error"
                break
            continue  # complete/heartbeat — data: line neeche hi aayegi
        if line.startswith("data:"):
            try:
                arr = json.loads(line[5:].strip())
            except Exception:
                continue
            if isinstance(arr, list) and arr:
                item = arr[0]
                if isinstance(item, dict) and item.get("url"):
                    out_url = item["url"]
                    seed = arr[1] if len(arr) > 1 else None
                elif isinstance(item, str):
                    gerr = "flux-space: " + item[:120]
    return out_url, seed, ms(), gerr

def gemini_image_fallback(prompt, ratio):
    """Gemini free-key image leg — nano-banana/3.1 models generateContent se b64 image.
    (NVIDIA fail ho tabhi aayega; quota reset/nyi key pe auto chalega)
    Returns (payload|None, elapsed_ms, err|None)."""
    t0 = time.time()
    ms = lambda: round((time.time() - t0) * 1000, 1)
    body = json.dumps({"contents": [{"parts": [{"text": prompt[:2000]}]}],
                       "generationConfig": {"responseModalities": ["IMAGE"]}}).encode("utf-8")
    last = None
    for model in GEMINI_IMAGE_MODELS:
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               + model + ":generateContent")
        req = urllib.request.Request(
            url, data=body,
            headers={"x-goog-api-key": GEMINI_KEY, "Content-Type": "application/json",
                     "User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)"},
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:
                d = json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            try:
                e.read().decode("utf-8", "replace")
            except Exception:
                pass
            last = f"gemini {model} HTTP {e.code}"  # 429 quota / 404 -> agla model
            continue
        except Exception as e:
            last = f"gemini {model} error: {e}"
            continue
        cand = (d.get("candidates") or [{}])[0]
        for p in (((cand.get("content") or {}).get("parts")) or []):
            idta = p.get("inlineData") or {}
            if idta.get("data"):
                mime = (idta.get("mimeType") or "image/png").split("/")[-1]
                b64 = idta["data"]
                out = {"model": f"{model} (Gemini)", "prompt": prompt[:2000], "count": 1,
                       "images": [{"format": mime, "base64": b64,
                                   "data_url": f"data:image/{mime};base64,{b64}"}],
                       "fallback": f"primary upstream fail — Gemini {model} se generate hua"}
                return out, ms(), None
        last = f"gemini {model}: no image in response"
    return None, ms(), last

# Gemini free-key leg — nano-banana/3.1 image models (429 quota pe agla model try hota hai)
GEMINI_KEY = os.environ.get("GEMINI_KEY", "")  # set via Space secret (repo me key NAHI)
GEMINI_IMAGE_MODELS = ("gemini-3.1-flash-lite-image", "gemini-3.1-flash-image",
                       "gemini-2.5-flash-image")

def nv_image_fallback(prompt, ratio):
    """NVIDIA NIM flux-3-image-klein — ~1.8s me b64 JPG. Returns (payload|None, elapsed_ms, err|None)."""
    t0 = time.time()
    ms = lambda: round((time.time() - t0) * 1000, 1)
    body = {"prompt": prompt[:2000], "cfg_scale": 4.0, "steps": 4,
            "seed": int(time.time()) % 2147483647}
    ar = NV_RATIO_MAP.get(ratio)
    if ar:
        body["aspect_ratio"] = ar
    req = urllib.request.Request(
        NV_IMAGE_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": "Bearer " + NV_IMAGE_KEY,
                 "Accept": "application/json",
                 "Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            raw = json.loads(resp.read().decode("utf-8", "replace"))
        arts = raw.get("artifacts") or []
        b64 = ""
        if arts and isinstance(arts[0], dict):
            b64 = str(arts[0].get("base64") or arts[0].get("b64") or "")
        if not b64:
            return None, ms(), "nvidia: no artifact in response"
        sig = base64.b64decode((b64 + "==")[:len(b64) + 3])[:4]
        fmt = ("png" if sig[:4] == b"\x89PNG" else
               "jpg" if sig[:2] == b"\xff\xd8" else
               "webp" if sig[:4] == b"RIFF" else "jpg")
        out = {"model": "flux-3-image-klein (NVIDIA NIM)", "prompt": prompt[:2000],
               "count": 1,
               "images": [{"format": fmt, "base64": b64,
                           "data_url": f"data:image/{fmt};base64,{b64}"}],
               "fallback": "primary upstream fail — NVIDIA flux-3-image-klein se generate hua"}
        nseed = (arts[0] or {}).get("seed")
        if nseed is not None:
            out["seed"] = nseed
        return out, ms(), None
    except urllib.error.HTTPError as e:
        try:
            ebody = e.read().decode("utf-8", "replace")[:150]
        except Exception:
            ebody = ""
        return None, ms(), f"nvidia HTTP {e.code}: {ebody}"
    except Exception as e:
        return None, ms(), f"nvidia error: {e}"

def hf_image_fallback(prompt):
    """OpenRouter fail hone pe free HF Spaces se generate — 3-space chain.
    (FLUX.2-klein-4B -> FLUX.1-schnell -> FLUX.2-klein-9B). Returns (payload|None, elapsed_ms, err)."""
    t0 = time.time()
    ms = lambda: round((time.time() - t0) * 1000, 1)
    ratio = (request.args.get("aspect_ratio") or request.args.get("ratio") or "").strip()
    dims = IMG_RATIO_DIMS.get(ratio, (1024, 1024))
    try:
        w = int(request.args.get("width") or dims[0])
        h = int(request.args.get("height") or dims[1])
    except Exception:
        w, h = dims
    w = min(max(w, 256), 2048)
    h = min(max(h, 256), 2048)
    last_err = None
    for host, fn, kind, label in FLUX_SPACES:
        out_url, seed, sdt, serr = _flux_space_call(host, fn, kind, prompt, w, h)
        if out_url:
            fmt, b64 = "webp", None
            try:
                with urllib.request.urlopen(urllib.request.Request(
                        out_url, headers={"User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)"}), timeout=30) as resp:
                    img = resp.read()
                    ct = (resp.headers.get("Content-Type") or "").lower()
                fmt = "webp" if ("webp" in ct or out_url.endswith(".webp")) else ("png" if "png" in ct else "jpg")
                b64 = base64.b64encode(img).decode("ascii")
            except Exception:
                pass
            first = {"format": fmt, "url": out_url}
            if b64:
                first["base64"] = b64
                first["data_url"] = f"data:image/{fmt};base64,{b64}"
            out = {"model": label + " (HuggingFace Space)", "prompt": prompt[:2000],
                   "count": 1, "images": [first], "width": w, "height": h,
                   "fallback": f"primary upstream fail — {label.split('/')[-1]} (free space) se generate hua"}
            if seed is not None:
                out["seed"] = seed
            return out, ms(), None
        last_err = serr or "flux-space: unknown failure"
    return None, ms(), last_err

def image_generate(prompt, ep):
    """OpenRouter Image API (POST JSON) — Qwen/Turbo jaise 61+ models. Returns (payload, dt, err)."""
    model = (request.args.get("model") or "").strip() or DEFAULT_IMAGE_MODEL
    ratio = (request.args.get("aspect_ratio") or request.args.get("ratio") or "").strip()
    res = (request.args.get("resolution") or "").strip().upper()
    if ratio and not re.fullmatch(r"\d{1,2}:\d{1,2}", ratio):
        ratio = ""
    if res not in IMG_RESOLUTIONS:
        res = ""
    body = {"model": model, "prompt": prompt[:2000], "n": 1}
    if ratio:
        body["aspect_ratio"] = ratio
    if res:
        body["resolution"] = res
    req = urllib.request.Request(
        ep["url_template"] or "https://openrouter.ai/api/v1/images",
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": "Bearer " + (ep["upstream_key"] or ""),
                 "Content-Type": "application/json",
                 "User-Agent": "Mozilla/5.0 (AuraOSINT-Hub/1.0)",
                 "Accept": "application/json"},
        method="POST")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            raw = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            ebody = json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            ebody = {}
        emsg = ((ebody.get("error") or {}).get("message")) or f"image upstream HTTP {e.code}"
        fb, fbd, ferr = hf_image_fallback(prompt)  # OpenRouter fail -> HF FLUX chain (NVIDIA pehle hi try ho chuka hai)
        if fb:
            return fb, round(round((time.time() - t0) * 1000, 1) + fbd, 1), None
        if ferr:
            emsg = emsg + "; " + ferr
        return None, round((time.time() - t0) * 1000, 1), emsg
    except Exception as e:
        fb, fbd, ferr = hf_image_fallback(prompt)
        if fb:
            return fb, round(round((time.time() - t0) * 1000, 1) + fbd, 1), None
        return None, round((time.time() - t0) * 1000, 1), \
            (f"image upstream error: {e}" + (f"; {ferr}" if ferr else ""))
    dt = round((time.time() - t0) * 1000, 1)
    items = []
    for it in (raw.get("data") or []):
        if not isinstance(it, dict):
            continue
        b64 = it.get("b64_json") or it.get("b64") or ""
        if b64:
            fmt = it.get("format") or ("jpg" if it.get("mime", "").endswith("jpeg") else "png")
            items.append({"format": fmt, "base64": b64,
                          "data_url": f"data:image/{fmt};base64,{b64}"})
        elif it.get("url"):
            items.append({"format": it.get("format") or "png", "url": it["url"]})
    if not items:
        return None, dt, "image upstream returned no images"
    out = {"model": model, "prompt": prompt[:2000], "count": len(items), "images": items}
    if ratio:
        out["aspect_ratio"] = ratio
    if res:
        out["resolution"] = res
    if raw.get("usage"):
        out["usage"] = raw["usage"]
    return out, dt, None

# ------------------------------------------------------------------ API API
# type param -> internal slug aliases
TYPE_MAP = {
    "tg_to_num": "tg", "tg2num": "tg", "tg2number": "tg", "telegram": "tg", "tg": "tg",
    "mobile": "num", "num": "num", "number": "num", "num_info": "num", "numcmd": "num",
    "pak_info": "numpak", "pak": "numpak", "numpak": "numpak", "pakistan_sim": "numpak",
    "sim_info": "numpak", "paknum": "numpak",
    "osint": "osint", "osint_search": "osint", "multi": "osint",
    "ip": "ip", "ip_info": "ip", "ipinfo": "ip", "ip_lookup": "ip", "ipinfo2": "ip",
    "aadhr": "aadhr", "aadhar": "aadhr", "aadhaar": "aadhr", "uidai": "aadhr", "aadhaar_info": "aadhr",
    "pincode": "pincode", "pin": "pincode", "pin_code": "pincode", "pincode_search": "pincode", "pinsearch": "pincode",
    "ifsc": "ifsc", "ifsc_info": "ifsc", "ifsc_search": "ifsc", "ifsc_lookup": "ifsc", "bank_branch": "ifsc",
    "insta": "insta", "ig": "insta", "instagram": "insta", "insta_info": "insta", "instainfo": "insta", "instagram_info": "insta",
    "snap": "snap", "snapchat": "snap", "snap_info": "snap", "snapchat_info": "snap", "snapchat_lookup": "snap",
    "domain": "domain", "whois": "domain", "domain_info": "domain", "site_info": "domain", "website_info": "domain", "url_info": "domain",
    "leak": "leak", "leak_info": "leak", "leakinfo": "leak", "leak_search": "leak", "leaksearch": "leak", "db_leak": "leak",
    "image": "image", "img": "image", "image_gen": "image", "imagegen": "image", "generate_image": "image",
    "ai_image": "image", "text2img": "image", "make_image": "image", "pic": "image",
    "imei": "imei", "imei_info": "imei", "imeilookup": "imei", "imei_lookup": "imei", "device_info": "imei", "tac": "imei",
    "upi": "upi", "upi_info": "upi", "upilookup": "upi", "upi_lookup": "upi", "vpa": "upi", "vpa_info": "upi", "upi_verify": "upi",
    "ff": "ff", "ff_info": "ff", "freefire": "ff", "ffid": "ff", "ffid_info": "ff", "ff_account": "ff",
}
TYPE_LIST = "tg_to_num, mobile, pak_info, osint, ip, aadhr, pincode, ifsc, insta, snap, domain, leak, image, imei, upi, ff"

@app.route("/api")
def api_typed():
    """Single-endpoint style: /api?key=KEY&type=tg_to_num&term=..."""
    t = (request.args.get("type") or "").strip().lower()
    if not t:
        return json_out(api_error(None, "unknown", 400, "Missing type parameter",
                                  f"add type param: {TYPE_LIST} (or call /api/<type>)")[0], 400)
    slug = TYPE_MAP.get(t)
    if not slug:
        return json_out(api_error(None, t[:40], 404, f"Unknown type '{t[:40]}'",
                                  f"available types: {TYPE_LIST}")[0], 404)
    return serve_api(slug)

@app.route("/api/<slug>")
def api_entry(slug):
    """Direct style: /api/num, /api/tg ... (type aliases bhi batenge)."""
    mapped = TYPE_MAP.get(slug)
    if mapped and mapped != slug:
        return serve_api(mapped)
    return serve_api(slug)

def serve_api(slug):
    ep = get_endpoint(slug)
    kv = request.args.get("key", "").strip()
    g.api_slug = slug  # apply_key_style ka __ENDPOINT__ iska use karega

    if not ep:
        env, code = api_error(None, slug, 404, "Unknown endpoint")
        return json_out(env, code)
    if not ep["enabled"]:
        env, code = api_error(None, slug, 503, "Endpoint under maintenance",
                              get_setting("maintenance_message", "API is currently under maintenance."))
        return json_out(env, code)

    term = first_term()
    key_row = get_key_raw(kv)

    if not kv or not key_row:
        env, code = api_error(None, slug, 401, "Invalid API key")
        return json_out(env, code)
    if not key_row["is_active"]:
        env, code = api_error(key_row, slug, 403, "Key disabled")
        return json_out(env, code)
    if is_expired(key_row):
        env, code = api_error(key_row, slug, 410, "Key expired")
        return json_out(env, code)
    if not key_allowed_for(key_row, slug):
        env, code = api_error(key_row, slug, 403, "Key not allowed for this endpoint")
        return json_out(env, code)
    if not term:
        env, code = api_error(key_row, slug, 400, "Missing search term",
                              f"add one of the params: {', '.join(TERMS)}")
        return json_out(env, code)
    if slug == "ifsc":
        term = term.upper()
        if not IFSC_RE.match(term):
            env, code = api_error(key_row, slug, 404, "Invalid IFSC code",
                                  "IFSC format is: BANK0XXXXXX (11 chars, 5th char '0')")
            return json_out(env, code)

    # ---- limits
    days_left, exp_on = remaining_days(key_row["expires_at"])
    today = today_str()
    used_today = key_row["today_hits"] if key_row["today_date"] == today else 0
    epoch = int(time.time())
    minute_used = key_row["minute_hits"] if (epoch - (key_row["minute_start"] or 0)) < 60 else 0

    if key_row["usage_mode"] == "rate_limited":
        if key_row["daily_limit"] > 0 and used_today >= key_row["daily_limit"]:
            env, code = api_error(key_row, slug, 429, "Daily limit reached",
                                  f"daily_limit={key_row['daily_limit']} — resets at midnight IST")
            return json_out(env, code)
        if key_row["per_min_limit"] > 0 and minute_used >= key_row["per_min_limit"]:
            env, code = api_error(key_row, slug, 429, "Per-minute limit reached",
                                  f"per_min={key_row['per_min_limit']}")
            return json_out(env, code)

    # ---- upstream (L1 memo -> L2 db cache -> live fetch)
    ttl = cache_ttl_minutes()
    ck = slug + "|" + term
    cached_payload = memcache_get(ck) if ttl > 0 else None
    if cached_payload is not None:
        is_cached = True
    else:
        cached_payload = cache_get(slug, term) if ttl > 0 else None
        is_cached = cached_payload is not None
        if is_cached:
            memcache_put(ck, cached_payload)   # L2 hit -> L1 me bhi dalo

    if is_cached:
        payload, dt, err = cached_payload, 0.0, None
        if slug == "tg" and isinstance(payload, dict):
            payload = dict(payload)
            payload["cached"] = True
    elif slug == "insta":
        # primary sahilxher + backup IG-meta scraper (upstream off ho to bhi response)
        payload, dt, err = fetch_insta_with_backup(ep, term)
    elif slug == "domain":
        # hamara apna multi-source domain OSINT (RDAP + DNS + IP + HTTP, parallel)
        payload, dt, err = domain_lookup(term)
    elif slug == "leak":
        # supabase leak-DB lookup (keyless) — Indian mobile number validate karke 10-digit bhejo
        t10 = re.sub(r"\D", "", term.strip())
        if not re.fullmatch(r"(91|0)?[6-9]\d{9}", t10):
            payload, dt, err = None, 0.0, "invalid phone number format"
        else:
            term = t10[-10:]
            payload, dt, err = fetch_upstream(ep, term)
            if isinstance(payload, dict):
                payload = normalize_leak(payload, term)
    elif slug == "upi":
        # Airtel paydigi unauth UPI verify — VPA ya mobile-number sweep (14 PSP handles)
        payload, dt, err = upi_lookup(term)
    elif slug == "imei":
        # local TAC database (11.8MB CSV) — Luhn + brand/model, zero upstream, kabhi down nahi
        payload, dt, err = imei_lookup(term)
    elif slug == "image":
        # Image generation — user ki NVIDIA key (flux-3-image-klein) PRIMARY,
        # OpenRouter backup, HF Space chain sabse akhir (Pollinations REMOVED)
        if len(term) < 3:
            payload, dt, err = None, 0.0, "prompt is too short (min 3 chars)"
        else:
            term = term[:2000]
            ratio = (request.args.get("aspect_ratio") or request.args.get("ratio") or "").strip()
            t_all = time.time()
            fb, fbd, ferr = nv_image_fallback(term, ratio)   # NVIDIA NIM pehla — ~2s
            if fb:
                payload, dt, err = fb, round((time.time() - t_all) * 1000, 1), None
            else:
                fg, fgd, gerr = gemini_image_fallback(term, ratio)  # Gemini leg (free key)
                if fg:
                    payload, dt, err = fg, round((time.time() - t_all) * 1000, 1), None
                else:
                    payload2, dt2, err2 = image_generate(term, ep)  # OpenRouter -> HF fallback chain
                    payload, dt, err = payload2, round((time.time() - t_all) * 1000, 1), err2
    else:
        payload, dt, err = fetch_upstream(ep, term)
        if slug == "tg":
            def _tg_ok(p):
                if not isinstance(p, dict):
                    return False
                plist = p.get("phone")
                if isinstance(plist, list) and len(plist) > 0:
                    return True
                if p.get("phone_number"):
                    return True
                if isinstance(p.get("data"), dict) and bool(str(p["data"].get("phone_number") or "").strip()):
                    return True
                return False
            if not _tg_ok(payload):
                # DEEP RETRY — upstream flaky hai (empty data / "Failed to fetch" / timeout).
                # 3 aur attempts, @username aur plain username alternate formats ke saath —
                # jo record upstream DB me hai, wo ab miss nahi hoga.
                sterm = term.strip().lstrip("@")
                variants = [sterm, sterm, sterm] if sterm.isdigit() \
                    else ["@" + sterm, sterm, "@" + sterm]
                for v in variants:
                    r2, d2, _e2 = tg_fetch_url(ep, v)
                    dt = round(dt + (d2 or 0), 1)
                    if _tg_ok(r2):
                        payload, err = r2, None
                        break
                    if r2 is not None:
                        payload = r2  # latest raw rakho (normalize raw-message ke liye)
            if isinstance(payload, dict) and not _tg_ok(payload):
                # tgosint fallback (unka backend wapas aaye to khud chalega)
                fb = tg_fallback_payload(term)
                if fb:
                    payload = fb
            if payload is None:
                # sab attempts fail — clean "Details not found" style (502 ke bajaye)
                payload, err = {"success": False, "data": {}}, None
        if slug in ("num", "osint") and (payload is None or (
                isinstance(payload, dict) and (payload.get("success") is False
                                               or payload.get("status") is False))):
            # keyed upstream mara (key expire / upstream error) — keyless leak-DB backup try karo
            t10 = re.sub(r"\D", "", term.strip())[-10:]
            if re.fullmatch(r"[6-9]\d{9}", t10):
                fb, fbd = leak_fallback_direct(t10)
                if fb:
                    payload = fb
                    dt = round(dt + fbd, 1)

    # error handling SAB slugs ke liye (insta bhi)
    if not is_cached and payload is None:
        if slug == "ifsc" and "HTTP 404" in (err or ""):
            env, code = api_error(key_row, slug, 404, "IFSC not found",
                                  "invalid or unknown IFSC code: " + term)
            return json_out(env, code)
        if slug == "domain" and ("does not exist" in (err or "").lower()
                                 or "invalid" in (err or "").lower()
                                 or "could not parse" in (err or "").lower()):
            env, code = api_error(key_row, slug, 404, "Domain not found",
                                  err or "no DNS records found for this website")
            return json_out(env, code)
        if slug == "insta" and "not found" in (err or "").lower():
            env, code = api_error(key_row, slug, 404, "Instagram user not found",
                                  "no Instagram profile found for: " + term)
            return json_out(env, code)
        if slug == "snap" and ("not found" in (err or "").lower() or "404" in (err or "")):
            env, code = api_error(key_row, slug, 404, "Snapchat user not found",
                                  "no Snapchat profile found for: " + term)
            return json_out(env, code)
        if slug == "leak" and "invalid" in (err or "").lower():
            env, code = api_error(key_row, slug, 400, "Invalid phone number",
                                  "use Indian mobile number, e.g. 9628060865")
            return json_out(env, code)
        if slug == "ff" and "http 404" in (err or "").lower():
            env, code = api_error(key_row, slug, 404, "Free Fire account not found",
                                  "no Free Fire account exists for this UID: " + term)
            return json_out(env, code)
        if slug == "upi" and "rate-limited" in (err or "").lower():
            env, code = api_error(key_row, slug, 429, "UPI upstream busy",
                                  "Airtel UPI gateway rate-limited ho gaya — koi seconds me retry karo")
            return json_out(env, code)
        if slug == "upi" and "invalid" in (err or "").lower():
            env, code = api_error(key_row, slug, 400, "Invalid input",
                                  "pass a 10-digit mobile number OR a VPA like name@ybl")
            return json_out(env, code)
        if slug == "upi" and ("not valid" in (err or "").lower()
                              or "no upi" in (err or "").lower()):
            env, code = api_error(key_row, slug, 404, "UPI not found",
                                  "no valid UPI ID / VPA found for: " + term[:60])
            return json_out(env, code)
        if slug == "imei" and "invalid imei" in (err or "").lower():
            env, code = api_error(key_row, slug, 400, "Invalid IMEI",
                                  "IMEI must be exactly 15 digits (e.g. 861536030196001)")
            return json_out(env, code)
        if slug == "imei" and "not found" in (err or "").lower():
            env, code = api_error(key_row, slug, 404, "Device not found",
                                  "TAC (first 8 digits) is not registered in our TAC database — "
                                  "device may be unlisted, cloned or non-GSMA")
            return json_out(env, code)
        if slug == "image" and "prompt is too short" in (err or ""):
            env, code = api_error(key_row, slug, 400, "Prompt too short",
                                  "write at least 3 characters of image description")
            return json_out(env, code)
        if slug == "image" and "no images" in (err or "").lower():
            env, code = api_error(key_row, slug, 502, "Image generation failed",
                                  "upstream could not generate an image for this prompt")
            return json_out(env, code)
        if slug == "image" and "permissions" in (err or "").lower():
            env, code = api_error(key_row, slug, 502, "Image upstream permissions missing",
                                  "OpenRouter has no credits AND HuggingFace token lacks 'Inference "
                                  "Providers' permission — fix either side, this endpoint is ready")
            return json_out(env, code)
        if slug == "image" and "insufficient credits" in (err or "").lower():
            env, code = api_error(key_row, slug, 502, "Image upstream out of credits",
                                  "OpenRouter account has no credits — add credits at "
                                  "openrouter.ai/settings/credits, this endpoint works instantly with the same key")
            return json_out(env, code)
        env, code = api_error(key_row, slug, 502, "Upstream failure",
                              err or "unknown upstream error")
        return json_out(env, code)
    if not is_cached and payload is not None:
        uerr = upstream_error_text(payload)
        if uerr:
            env, code = api_error(key_row, slug, 502, "Upstream error", uerr)
            return json_out(env, code)
        if slug == "insta" and isinstance(payload, dict) and payload.get("success") is False:
            env, code = api_error(key_row, slug, 404, "User not found",
                                  (payload.get("message") or
                                   "no Instagram profile found for: " + term))
            return json_out(env, code)

    # ---- success path
    if not is_cached:
        if isinstance(payload, dict) and not payload:
            # upstream ne literal {} bheja (khaali) — clean error do, khaali 200 nahi
            env, code = api_error(key_row, slug, 502, "Upstream returned empty response",
                                  "no data in upstream response")
            return json_out(env, code)
        if slug == "tg":
            payload = normalize_tg(payload, term, False)
        if slug == "numpak":
            payload = normalize_pak(payload)
        if slug in ("osint", "aadhr", "pincode", "insta", "snap", "domain", "leak", "image", "imei", "upi", "ff") and isinstance(payload, dict):
            # response timing + usage tracking ki jankari (data ke end me, footer se pehle)
            payload["response_time_ms"] = int(round(dt))
            payload["usage_tracked"] = True
        if slug == "ifsc" and isinstance(payload, dict):
            # IFSC enrich: razorpay fast JSON -> user ke enriched format me (+ pincode location)
            t1 = time.time()
            payload = enrich_ifsc(payload, term)
            dt = round(dt + (time.time() - t1) * 1000, 1)
        if slug == "pincode" and isinstance(payload, dict) and not payload.get("total"):
            env, code = api_error(key_row, slug, 404, "Pincode not found",
                                  "no post offices found for: " + term)
            return json_out(env, code)
        if slug == "leak" and isinstance(payload, dict) and not payload.get("total"):
            env, code = api_error(key_row, slug, 404, "No leak data found",
                                  "no leak records found for: " + term)
            return json_out(env, code)
        if slug == "ip" and isinstance(payload, dict) and payload.get("status") == "fail":
            env, code = api_error(key_row, slug, 404, "IP not found",
                                  (payload.get("message") or "upstream could not resolve this IP"))
            return json_out(env, code)
        if ttl > 0 and isinstance(payload, dict) and payload and \
                not (slug == "tg" and payload.get("status") is False):
            # tg failures cache ME DAB na karo (normalize ke baad 'status' False hota hai
            # — pehle 'success' pe check kar raha the isliye fail code bhi 12h cache ho rahe the)
            cache_put(slug, term, payload)
            memcache_put(ck, payload)
    if slug == "ip" and isinstance(payload, dict):
        # ip-api "query" field ko clean "ip" field me rename karo (top pe) — cached pe bhi chale
        if "ip" not in payload and isinstance(payload.get("query"), str):
            q = payload.pop("query")
            payload = {"ip": q, **payload}
    core = build_envelope(payload, {**key_row,
                                    "today_hits": used_today})
    if slug == "tg":
        core = reorder_tg(core)
    hit = register_hit(key_row)
    envelope = apply_key_style(core, key_row, 200)
    preview = json.dumps(envelope, ensure_ascii=False)[:600]
    add_log(key_row, slug, term, 200, True, dt,
            ("key capped & disabled" if hit["capped"] else ("cache hit" if is_cached else "ok")), preview)
    # product style: data-object, phir },\n{ key_details/developer/success footer-object
    return split_output(envelope)

# -------------------------------------------------------------- public pages
@app.route("/")
def landing():
    eps = [e for e in all_endpoints() if e["enabled"]]
    return render_template("terminal.html", endpoints=eps, developer=developer_name())

@app.route("/docs")
def docs():
    eps = all_endpoints()
    return render_template("docs.html", base_url=request.host_url.rstrip("/"),
                           endpoints=eps, developer=developer_name(),
                           maintenance=get_setting("maintenance_message", ""))

@app.route("/terminal")
def terminal_page():
    return redirect("/")

@app.route("/info")
def info():
    hits = 0
    conn = db()
    row = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()
    hits = row["c"]
    keys = conn.execute("SELECT COUNT(*) c FROM api_keys").fetchone()["c"]
    conn.close()
    return render_template("info.html", developer=developer_name(), hits=hits, keys=keys)

# ------------------------------------------------------------------  admin
def _user_allowed(path):
    """user role in pages ko dekh sakta hai (GET only, actions head-admin hi)."""
    return (path == "/admin" or path.startswith("/admin/logs")
            or path.startswith("/admin/analytics") or path.startswith("/admin/endpoints"))

def admin_required(f):
    """Admin ya user-account — koi bhi logged-in staff; user-role sirf limited pages."""
    @wraps(f)
    def w(*a, **kw):
        if not (session.get("admin_id") or session.get("user_id")):
            return redirect(url_for("admin_login", next=request.path))
        if not session.get("admin_id") and not _user_allowed(request.path):
            flash("Ye section sirf head-admin ke liye hai.", "danger")
            return redirect(url_for("admin_dashboard"))
        if not session.get("admin_id") and request.method in ("POST", "PUT", "DELETE"):
            flash("Read-only account — actions head-admin hi kar sakta hai.", "danger")
            return redirect(url_for("admin_dashboard"))
        return f(*a, **kw)
    return w

def head_required(f):
    """Sirf head-admin routes (key/settings/users/security + sab mutating actions)."""
    @wraps(f)
    def w(*a, **kw):
        if not (session.get("admin_id") or session.get("user_id")):
            return redirect(url_for("admin_login", next=request.path))
        if not session.get("admin_id"):
            flash("Ye section sirf head-admin ke liye hai.", "danger")
            return redirect(url_for("admin_dashboard"))
        return f(*a, **kw)
    return w

def admin_row():
    aid = session.get("admin_id")
    if not aid:
        return None
    conn = db()
    row = conn.execute("SELECT * FROM admins WHERE id=?", (aid,)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

@app.template_filter("fmt_dt")
def fmt_dt(v):
    try:
        return datetime.strptime(v[:19], "%Y-%m-%d %H:%M:%S").strftime("%d/%m/%Y %I:%M%p").lower()
    except Exception:
        return v

@app.template_filter("dt_only")
def dt_only(v):
    try:
        return datetime.strptime(str(v)[:10], "%Y-%m-%d").strftime("%d/%m/%Y")
    except Exception:
        return str(v)

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        conn = db()
        a = conn.execute("SELECT * FROM admins WHERE username=?", (u,)).fetchone()
        if not a:
            a = conn.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
            if a:
                a = dict(a) | {"is_admin": False}
        else:
            a = dict(a) | {"is_admin": True}
        conn.close()
        if a and check_password_hash(a["password_hash"], p):
            if not a["is_admin"] and not a["is_active"]:
                log_login_attempt(u, "user", "blocked")
                flash("Account blocked. Admin se contact karo.", "danger")
                return render_template("login.html")
            log_login_attempt(u, a["role"] if a["is_admin"] else "user", "success")
            if a["is_admin"]:
                session["admin_id"] = a["id"]
                session["admin_role"] = a["role"]
                session["admin_name"] = a["username"]
            else:
                session["user_id"] = a["id"]
                session["admin_role"] = "user"
                session["admin_name"] = a["username"]
            return redirect(request.args.get("next") or url_for("admin_dashboard"))
        log_login_attempt(u, ("admin" if a and a["is_admin"] else ("user" if a else "unknown")), "invalid")
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = db()
    total = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    today = conn.execute("SELECT COUNT(*) c FROM logs WHERE created_at LIKE ?", (today_str() + "%",)).fetchone()["c"]
    keys_total = conn.execute("SELECT COUNT(*) c FROM api_keys").fetchone()["c"]
    keys_live = conn.execute("SELECT COUNT(*) c FROM api_keys WHERE is_active=1 AND (expires_at IS NULL OR expires_at>=?)",
                             (today_str(),)).fetchone()["c"]
    eps = all_endpoints()
    eps_online = len([e for e in eps if e["enabled"]])
    srow = conn.execute("SELECT COUNT(*) c FROM logs WHERE success=1").fetchone()["c"]
    rate = round((srow / total) * 100, 1) if total else 0.0

    daily = conn.execute(
        "SELECT substr(created_at,1,10) d, COUNT(*) c FROM logs GROUP BY d ORDER BY d DESC LIMIT 14"
    ).fetchall()
    daily = [{"d": r["d"], "c": r["c"]} for r in reversed(daily)]
    top = [{"l": r["endpoint"] or "?", "c": r["c"]}
           for r in conn.execute(
        "SELECT endpoint, COUNT(*) c FROM logs GROUP BY endpoint ORDER BY c DESC LIMIT 6").fetchall()]
    recent = conn.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT 10").fetchall()
    peak = conn.execute(
        "SELECT d, c FROM (SELECT substr(created_at,1,10) d, COUNT(*) c FROM logs GROUP BY d ORDER BY c DESC LIMIT 1)"
    ).fetchone()
    ep_rows = conn.execute(
        "SELECT endpoint ep, COUNT(*) c, SUM(success) ok, AVG(response_time) ms FROM logs GROUP BY endpoint"
    ).fetchall()
    ep_stats = {r["ep"] or "?": {"c": r["c"], "ok": r["ok"] or 0,
                                 "ms": round(r["ms"] or 0)} for r in ep_rows}
    avg_ms_row = conn.execute("SELECT AVG(response_time) m FROM logs").fetchone()
    conn.close()
    return render_template("dashboard.html", total=total, today=today,
                           keys_total=keys_total, keys_live=keys_live,
                           eps=eps, eps_online=eps_online, rate=rate,
                           daily=daily, top=top, recent=recent,
                           ep_stats=ep_stats, avg_ms=round(avg_ms_row["m"] or 0),
                           peak=peak["c"] if peak else 0,
                           maintenance=get_setting("maintenance_message", ""),
                           uptime=_uptime(), admin=admin_row())

def _boot_time():
    global _BOOT
    return _BOOT

_BOOT = datetime.now()

def _uptime():
    d = datetime.now() - _BOOT
    h, m = d.seconds // 3600, (d.seconds % 3600) // 60
    days = d.days
    parts = []
    if days: parts.append(f"{days}d")
    if h: parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)

@app.route("/admin/keys")
@admin_required
def admin_keys():
    status = request.args.get("status", "all")
    q = request.args.get("q", "").strip()
    sql = "SELECT * FROM api_keys WHERE 1=1"
    args = []
    today = today_str()
    if status == "live":
        sql += " AND is_active=1 AND (expires_at IS NULL OR expires_at>=?)"
        args.append(today)
    elif status == "expired":
        sql += " AND expires_at IS NOT NULL AND expires_at<?"
        args.append(today)
    elif status == "off":
        sql += " AND is_active=0"
    if q:
        sql += " AND (key LIKE ? OR client LIKE ? OR note LIKE ?)"
        args += [f"%{q}%"] * 3
    sql += " ORDER BY id DESC"
    conn = db()
    keys = conn.execute(sql, args).fetchall()
    eps = all_endpoints()
    conn.close()
    return render_template("keys.html", keys=keys, eps=eps, status=status, q=q,
                           today=today_str(), admin=admin_row())

@app.route("/admin/keys/create", methods=["GET", "POST"])
@admin_required
def keys_create():
    if request.method == "GET":
        return redirect(url_for("admin_keys"))
    f = request.form
    kv = (f.get("key", "").strip() if f.get("custom_toggle") == "on" else "") \
         or secrets.token_hex(8)
    if get_key_raw(kv):
        flash(f"Key '{kv}' already exists.", "danger")
        return redirect(url_for("admin_keys"))
    access = "all"
    if f.get("access_mode") == "single" and f.get("single_ep"):
        access = f.get("single_ep")
    elif f.get("access_mode") == "multiple":
        chosen = ",".join(request.form.getlist("eps"))
        access = chosen if chosen else "all"
    usage = f.get("usage_mode", "unlimited")
    daily = int(f.get("daily_limit") or 0)
    permin = int(f.get("per_min_limit") or 0)
    cap = int(f.get("total_cap") or 0)
    validity = f.get("validity", "lifetime")
    expires = f"{today_str()}+{validity}"
    expires = None
    if validity == "custom":
        expires = f.get("custom_date") or None
    elif validity != "lifetime":
        expires = (datetime.now() + timedelta(days=int(validity))).strftime("%Y-%m-%d")
    conn = db()
    conn.execute(
        "INSERT INTO api_keys(key,client,note,allowed,usage_mode,daily_limit,per_min_limit,total_cap,"
        "is_active,expires_at,style_developer,style_template,created_at) VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?)",
        (kv, f.get("client", "").strip(), f.get("note", "").strip(), access, usage, daily, permin, cap,
         expires, f.get("style_developer", "").strip(), f.get("style_template", "").strip(), now_iso()))
    conn.commit(); conn.close()
    flash(f"Key created: {kv}", "success")
    return redirect(url_for("admin_keys"))

@app.route("/admin/keys/<int:kid>/update", methods=["POST"])
@admin_required
def keys_update(kid):
    f = request.form
    access = "all"
    if f.get("access_mode") == "single" and f.get("single_ep"):
        access = f.get("single_ep")
    elif f.get("access_mode") == "multiple":
        chosen = ",".join(request.form.getlist("eps"))
        access = chosen if chosen else "all"
    expires = None
    validity = f.get("validity", "lifetime")
    if validity == "custom":
        expires = f.get("custom_date") or None
    elif validity != "lifetime":
        expires = (datetime.now() + timedelta(days=int(validity))).strftime("%Y-%m-%d")
    conn = db()
    conn.execute(
        "UPDATE api_keys SET client=?, note=?, allowed=?, usage_mode=?, daily_limit=?, per_min_limit=?, "
        "total_cap=?, expires_at=?, style_developer=?, style_template=? WHERE id=?",
        (f.get("client", "").strip(), f.get("note", "").strip(), access,
         f.get("usage_mode", "unlimited"), int(f.get("daily_limit") or 0),
         int(f.get("per_min_limit") or 0), int(f.get("total_cap") or 0),
         expires, f.get("style_developer", "").strip(), f.get("style_template", "").strip(), kid))
    conn.commit(); conn.close()
    flash("Key updated.", "success")
    return redirect(request.form.get("back") or url_for("admin_keys"))

def _key_action(kid, sql_single, args=()):
    conn = db()
    conn.execute(sql_single, (*args, kid))
    conn.commit(); conn.close()

@app.route("/admin/keys/<int:kid>/toggle", methods=["POST"])
@admin_required
def key_toggle(kid):
    _key_action(kid, "UPDATE api_keys SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id=?")
    return jsonify(ok=True)

@app.route("/admin/keys/<int:kid>/reset", methods=["POST"])
@admin_required
def key_reset(kid):
    conn = db()
    conn.execute(
        "UPDATE api_keys SET total_hits=0, today_hits=0, today_date='', minute_hits=0, minute_start=0, "
        "is_active=1 WHERE id=?", (kid,))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route("/admin/keys/<int:kid>/extend", methods=["POST"])
@admin_required
def key_extend(kid):
    days = int(request.form.get("days") or 30)
    conn = db()
    row = conn.execute("SELECT expires_at FROM api_keys WHERE id=?", (kid,)).fetchone()
    base = None
    if row and row["expires_at"]:
        try:
            base = datetime.strptime(row["expires_at"][:10], "%Y-%m-%d")
        except Exception:
            base = None
    if not base or base < datetime.now():
        base = datetime.now()
    conn.execute("UPDATE api_keys SET expires_at=?, is_active=1 WHERE id=?",
                 ((base + timedelta(days=days)).strftime("%Y-%m-%d"), kid))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route("/admin/keys/<int:kid>/delete", methods=["POST"])
@admin_required
def key_delete(kid):
    conn = db()
    conn.execute("DELETE FROM api_keys WHERE id=?", (kid,))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route("/admin/keys/bulk", methods=["POST"])
@admin_required
def keys_bulk():
    action = request.form.get("bulk_action")
    ids = [int(i) for i in request.form.getlist("ids") if str(i).isdigit()]
    if not ids:
        return jsonify(ok=False, error="no keys selected"), 400
    conn = db()
    marks = ",".join("?" * len(ids))
    if action == "enable":
        conn.execute(f"UPDATE api_keys SET is_active=1 WHERE id IN ({marks})", ids)
    elif action == "disable":
        conn.execute(f"UPDATE api_keys SET is_active=0 WHERE id IN ({marks})", ids)
    elif action == "activate":
        conn.execute(f"UPDATE api_keys SET is_active=1, expires_at=NULL WHERE id IN ({marks})", ids)
    elif action == "reset":
        conn.execute(f"UPDATE api_keys SET total_hits=0, today_hits=0, today_date='', minute_hits=0, "
                     f"minute_start=0, is_active=1 WHERE id IN ({marks})", ids)
    elif action == "extend":
        piece = ",".join("id=?" and "?" for _ in [])  # silence
        for kid in ids:
            row = conn.execute("SELECT expires_at FROM api_keys WHERE id=?", (kid,)).fetchone()
            base = datetime.now()
            if row and row["expires_at"]:
                try:
                    e = datetime.strptime(row["expires_at"][:10], "%Y-%m-%d")
                    if e > base: base = e
                except Exception:
                    pass
            conn.execute("UPDATE api_keys SET expires_at=?, is_active=1 WHERE id=?",
                         ((base + timedelta(days=30)).strftime("%Y-%m-%d"), kid))
    elif action == "delete":
        conn.execute(f"DELETE FROM api_keys WHERE id IN ({marks})", ids)
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route("/admin/keys/<int:kid>/download")
@admin_required
def key_download(kid):
    conn = db()
    k = conn.execute("SELECT * FROM api_keys WHERE id=?", (kid,)).fetchone()
    conn.close()
    if not k:
        flash("Key not found.", "danger")
        return redirect(url_for("admin_keys"))
    days, expires_on = remaining_days(k["expires_at"])
    dev = k["style_developer"] or developer_name()
    lines = [
        "AURA OSINT HUB - API Key Details",
        "=" * 40,
        f"key:         {k['key']}",
        f"client:      {k['client'] or '-'}",
        f"note:        {k['note'] or '-'}",
        f"access:      {k['allowed']}",
        f"usage_mode:  {k['usage_mode']}",
        f"daily_limit: {k['daily_limit']}",
        f"per_min:     {k['per_min_limit']}",
        f"total_cap:   {k['total_cap']}",
        f"total_hits:  {k['total_hits']}",
        f"expires_on:  {expires_on}" + (f" ({days}d left)" if k['expires_at'] else ""),
        f"developer:   {dev}",
        f"created_at:  {k['created_at']}",
        "",
        "API examples (apna base URL lagao):",
        f"GET /api?key={k['key']}&type=pak_info&term=923001234567",
        f"GET /api?key={k['key']}&type=ip&ip=8.8.8.8",
        f"GET /api?key={k['key']}&type=osint&term=911234567890",
    ]
    txt = "\n".join(lines)
    return Response(txt, mimetype="text/plain",
                    headers={"Content-Disposition": f"attachment; filename=api-key-{k['key']}.txt"})

@app.route("/admin/keys/<int:kid>")
@admin_required
def key_detail(kid):
    conn = db()
    k = conn.execute("SELECT * FROM api_keys WHERE id=?", (kid,)).fetchone()
    if not k:
        conn.close(); return redirect(url_for("admin_keys"))
    logs = conn.execute("SELECT * FROM logs WHERE key_id=? ORDER BY id DESC LIMIT 200", (kid,)).fetchall()
    conn.close()
    endpoints = {e["slug"]: e for e in all_endpoints()}
    return render_template("key_detail.html", k=k, logs=logs, endpoints=endpoints, admin=admin_row())

# ------------------------------------------------------------- endpoint admin
@app.route("/admin/endpoints")
@admin_required
def admin_endpoints():
    eps = all_endpoints()
    return render_template("endpoints.html", eps=eps, admin=admin_row())

@app.route("/admin/endpoints/create", methods=["POST"])
@admin_required
def ep_create():
    f = request.form
    slug = (f.get("slug") or "").strip().lower().replace(" ", "")
    if not slug or get_endpoint(slug):
        flash("Endpoint slug missing or already exists.", "danger")
        return redirect(url_for("admin_endpoints"))
    conn = db()
    conn.execute("INSERT INTO endpoints(slug,name,emoji,url_template,upstream_key,term_param,sort_order,created_at)"
                 " VALUES(?,?,?,?,?,?,?,?)",
                 (slug, f.get("name") or slug, f.get("emoji") or "🔌",
                  f.get("url_template") or "", f.get("upstream_key") or "",
                  f.get("term_param") or "term", 500, now_iso()))
    conn.commit(); conn.close()
    flash(f"Endpoint /api/{slug} created.", "success")
    return redirect(url_for("admin_endpoints"))

@app.route("/admin/endpoints/<int:eid>/update", methods=["POST"])
@admin_required
def ep_update(eid):
    f = request.form
    conn = db()
    conn.execute("UPDATE endpoints SET name=?, emoji=?, url_template=?, upstream_key=? WHERE id=?",
                 (f.get("name"), f.get("emoji"), f.get("url_template"),
                  f.get("upstream_key"), eid))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route("/admin/endpoints/<int:eid>/toggle", methods=["POST"])
@admin_required
def ep_toggle(eid):
    conn = db()
    conn.execute("UPDATE endpoints SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?", (eid,))
    conn.commit()
    row = conn.execute("SELECT enabled FROM endpoints WHERE id=?", (eid,)).fetchone()
    conn.close()
    return jsonify(ok=True, enabled=bool(row["enabled"]) if row else None)

@app.route("/admin/endpoints/<int:eid>/delete", methods=["POST"])
@admin_required
def ep_delete(eid):
    conn = db()
    conn.execute("DELETE FROM endpoints WHERE id=?", (eid,))
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route("/admin/endpoints/<int:eid>/test", methods=["POST"])
@admin_required
def ep_test(eid):
    conn = db()
    ep = conn.execute("SELECT * FROM endpoints WHERE id=?", (eid,)).fetchone()
    conn.close()
    if not ep:
        return jsonify(ok=False, error="not found")
    term = request.form.get("term") or "1"
    payload, dt, err = fetch_upstream(ep, term)
    if payload is None:
        return jsonify(ok=False, ms=dt, error=err)
    return jsonify(ok=True, ms=dt, preview=json.dumps(payload, ensure_ascii=False)[:800])

@app.route("/admin/endpoints/bulk", methods=["POST"])
@admin_required
def ep_bulk():
    action = request.form.get("bulk_action")
    conn = db()
    if action == "enable_all":
        conn.execute("UPDATE endpoints SET enabled=1")
    elif action == "disable_all":
        conn.execute("UPDATE endpoints SET enabled=0")
    conn.commit(); conn.close()
    return jsonify(ok=True)

# ---------------------------------------------------------------- logs admin
@app.route("/admin/logs")
@admin_required
def admin_logs():
    q = request.args.get("q", "").strip()
    ep = request.args.get("ep", "")
    status = request.args.get("status", "")   # ok | fail
    date = request.args.get("date", "")
    sql = "SELECT * FROM logs WHERE 1=1"
    args = []
    if q:
        sql += " AND (term LIKE ? OR key_string LIKE ? OR key_id LIKE ?)"
        args += [f"%{q}%"] * 3
    if ep:
        sql += " AND endpoint=?"
        args.append(ep)
    if status == "ok":
        sql += " AND success=1"
    elif status == "fail":
        sql += " AND success=0"
    if date:
        sql += " AND substr(created_at,1,10)=?"
        args.append(date)
    sql += " ORDER BY id DESC LIMIT 400"
    conn = db()
    logs = conn.execute(sql, args).fetchall()
    eps = all_endpoints()
    conn.close()
    return render_template("logs.html", logs=logs, eps=eps, q=q, ep=ep, status=status, date=date,
                           admin=admin_row())

@app.route("/admin/logs/<int:lid>")
@admin_required
def log_detail(lid):
    conn = db()
    row = conn.execute("SELECT * FROM logs WHERE id=?", (lid,)).fetchone()
    conn.close()
    if not row:
        return jsonify(ok=False), 404
    return jsonify(ok=True, log=dict(row))

@app.route("/admin/logs/clear", methods=["POST"])
@admin_required
def logs_clear():
    conn = db()
    conn.execute("DELETE FROM logs")
    conn.commit(); conn.close()
    return jsonify(ok=True)

@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    conn = db()
    daily = [{'d': r['d'], 'c': r['c']} for r in reversed(conn.execute(
        "SELECT substr(created_at,1,10) d, COUNT(*) c FROM logs GROUP BY d ORDER BY d DESC LIMIT 21").fetchall())]
    top_eps = [{'l': r['endpoint'] or '?', 'c': r['c']} for r in conn.execute(
        "SELECT endpoint, COUNT(*) c FROM logs GROUP BY endpoint ORDER BY c DESC LIMIT 8").fetchall()]
    top_keys = [{'k': r['key_string'], 'kid': r['key_id'], 'c': r['c']} for r in conn.execute(
        "SELECT l.key_string, l.key_id, COUNT(*) c FROM logs l GROUP BY l.key_string ORDER BY c DESC LIMIT 10"
    ).fetchall()]
    total = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"] or 0
    ok = conn.execute("SELECT COUNT(*) c FROM logs WHERE success=1").fetchone()["c"]
    avg = conn.execute("SELECT ROUND(AVG(response_time),1) a FROM logs WHERE success=1").fetchone()["a"]
    conn.close()
    rate = round((ok / total) * 100, 1) if total else 0.0
    return render_template("analytics.html", daily=daily, top_eps=top_eps, top_keys=top_keys,
                           total=total, rate=rate, avg=avg or 0, admin=admin_row())

@app.route("/admin/security")
@admin_required
def admin_security():
    conn = db()
    attempts = conn.execute("SELECT * FROM login_attempts ORDER BY id DESC LIMIT 300").fetchall()
    failed = conn.execute("SELECT COUNT(*) c FROM login_attempts WHERE status='invalid'").fetchone()["c"]
    ok = conn.execute("SELECT COUNT(*) c FROM login_attempts WHERE status='success'").fetchone()["c"]
    conn.close()
    return render_template("security.html", attempts=attempts, failed=failed, ok=ok, admin=admin_row())

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        what = request.form.get("what")
        if what == "brand":
            set_setting("developer", (request.form.get("developer") or "").strip())
            set_setting("maintenance_message", (request.form.get("maintenance_message") or "").strip())
            flash("Settings saved.", "success")
        elif what == "password":
            cur = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            a = admin_row()
            if not a or not check_password_hash(a["password_hash"], cur):
                flash("Current password wrong.", "danger")
            elif len(new) < 6:
                flash("New password too short (min 6).", "danger")
            else:
                conn = db()
                conn.execute("UPDATE admins SET password_hash=? WHERE id=?",
                             (generate_password_hash(new), a["id"]))
                conn.commit(); conn.close()
                flash("Password changed.", "success")
        return redirect(url_for("admin_settings"))
    return render_template("settings.html", developer=developer_name(),
                           maintenance=get_setting("maintenance_message", ""), admin=admin_row())

# ------------------------------------------------------------------ user accounts
@app.route("/admin/users")
@admin_required
def admin_users():
    if not session.get("admin_id"):
        flash("Ye section sirf head-admin ke liye hai.", "danger")
        return redirect(url_for("admin_dashboard"))
    conn = db()
    users = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("users.html", users=users, admin=admin_row())

@app.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_users_create():
    if not session.get("admin_id"):
        flash("Sirf head-admin allowed.", "danger")
        return redirect(url_for("admin_dashboard"))
    u = (request.form.get("username") or "").strip()
    p = request.form.get("password") or ""
    if not u or not p:
        flash("Username aur password dono required.", "danger")
        return redirect(url_for("admin_users"))
    if len(p) < 6:
        flash("Password min 6 characters.", "danger")
        return redirect(url_for("admin_users"))
    conn = db()
    exists = conn.execute("SELECT 1 x FROM users WHERE username=? UNION SELECT 1 FROM admins WHERE username=?",
                          (u, u)).fetchone()
    if exists:
        conn.close()
        flash("Ye username already exist karta hai.", "danger")
        return redirect(url_for("admin_users"))
    conn.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                 (u, generate_password_hash(p), now_iso()))
    conn.commit(); conn.close()
    flash(f"User '{u}' created ✅ — username + password share kar do.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:uid>/reset", methods=["POST"])
@admin_required
def admin_users_reset(uid):
    if not session.get("admin_id"):
        flash("Sirf head-admin allowed.", "danger")
        return redirect(url_for("admin_dashboard"))
    p = request.form.get("password") or ""
    if len(p) < 6:
        flash("New password min 6 characters.", "danger")
        return redirect(url_for("admin_users"))
    conn = db()
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(p), uid))
    conn.commit(); conn.close()
    flash("Password reset ✅", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def admin_users_toggle(uid):
    if not session.get("admin_id"):
        flash("Sirf head-admin allowed.", "danger")
        return redirect(url_for("admin_dashboard"))
    conn = db()
    row = conn.execute("SELECT is_active FROM users WHERE id=?", (uid,)).fetchone()
    if row:
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (0 if row["is_active"] else 1, uid))
        conn.commit()
    conn.close()
    flash("User unblock/block kar diya ✅", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_users_delete(uid):
    if not session.get("admin_id"):
        flash("Sirf head-admin allowed.", "danger")
        return redirect(url_for("admin_dashboard"))
    conn = db()
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit(); conn.close()
    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))

@app.after_request
def _mongo_auto_sync(response):
    if request.method in ("POST", "PUT", "DELETE", "PATCH") or request.path.startswith("/api/"):
        try:
            sync_to_mongo()
        except Exception:
            pass
    return response

# -------------------------------------------------------------------- boot
init_db()
sync_to_mongo(force=True)

if __name__ == "__main__":
    print(f"AURA OSINT HUB -> http://127.0.0.1:{PORT}   (login: /admin/login)", flush=True)
    app.run(host=HOST, port=PORT, debug=False)
