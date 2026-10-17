# ⚡ AURA OSINT HUB — API + Admin Panel

Apna khud ka OSINT API hub — 4 upstream APIs (Number Info, TG→Number, Pakistan SIM-DB, OSINT Search)
aapke **personal key system** ke piche wrapped, full **admin panel** ke saath (dark theme + sidebar).

## 🚀 Run

```bash
cd osint-hub
python app.py
```

- Live site / docs : `http://127.0.0.1:5005`
- Admin panel      : `http://127.0.0.1:5005/admin/login`
- Default creds    : `admin / aura@9751` (console me bhi print hota hai — Settings se change karo)
- Port change      : `PORT=8080 python app.py` (Windows PowerShell: `$env:PORT=8080`)

## 🔌 API

```
GET /api?key=YOUR_KEY&type={type}&term={input}
```
Ya direct endpoint style: `GET /api/<endpoint>?key=YOUR_KEY&term={input}`

| type= | Endpoint | Purpose | Example |
|---|---|---|---|
| `tg_to_num` | `/api/tg` | 📞 Telegram @username ya numeric User ID → number | `type=tg_to_num&term=Redoxlala` / `term=123456789` |
| `mobile` | `/api/num` | 🇮🇳 10-digit mobile → NAME/ADDRESS/aadhar/circle | `type=mobile&term=7549599202` |
| `pak_info` | `/api/numpak` | 🇵🇰 PK SIM (11-digit) → name/cnic/network | `type=pak_info&term=03455310824` |
| `osint` | `/api/osint` | 🔎 phone/email/IP/domain/name multi-db | `type=osint&term=918755178417` |

Search value inme se koi bhi param bhej do: `term | search | query | username | userid | number | q | value | id`

Galat/missing `type` → `404 Unknown type` ya `400 Missing type parameter` (available types message ke sath).

| Direct | Purpose | Example |
|---|---|---|
| `/api/num` | 🇮🇳 Number → NAME/ADDRESS/aadhar/circle | `?key=KEY&term=7549599202` |
| `/api/tg` | 📞 Telegram id/username → number | `?key=KEY&term=Redoxlala` ya `?key=KEY&term=123456789` (numeric → `userid=` auto) |
| `/api/numpak` | 🇵🇰 PK SIM → name/cnic/network | `?key=KEY&search=3455310824` |
| `/api/osint` | 🔎 OSINT email/name/ip/number | `?key=KEY&query=919709586997` |

Response me appka envelope: `...data...` + `key_details{used_today,daily_limit,valid_days,expires_on}`
+ `developer` + `success` + `status_code` + `http_status`. Errors bhi same envelope me aati hain.

Demo test key (pehli bar seed hoti hai): `DEMO123` — unlimited, lifetime. Admin panel se delete karo.

## 🎛 Admin panel features

- **Dashboard** — total requests, keys, endpoints online, success-rate, daily volume chart, top-endpoints donut, recent activity, maintenance-banner editor
- **API Keys** — generate (custom key string, client, note), access `All/Single/Multiple`, usage mode `Unlimited / Rate-limited (daily·per-min) / Fixed-cap`, validity (7d/30d/lifetime/custom date), **per-key response style** (developer override + custom JSON template with `__DATA__ __KEY_DETAILS__ __DEVELOPER__ __SUCCESS__ __STATUS_CODE__` placeholders), edit/delete/toggle/extend(+30d)/reset-hits, bulk actions (enable/disable/activate/reset/extend/delete), All/Live/Expired/Off filters + search
- **Search Logs** — har API hit ka log: key, endpoint, term, status, ms, IP, time + filters (endpoint/status/date/search) + response preview modal
- **Analytics** — 21-day volume, endpoint donut, top keys leaderboard
- **Endpoints** — cards with global on/off switches (customers ko maintenance error jaata hai), **Test** button (live upstream check + ms), edit upstream URL/key, **add your own generic endpoint** (`{upstream_key}` & `{term}` placeholders)
- **Security** — login attempts (user, role, IP, success/invalid)
- **Settings** — developer handle, maintenance banner, change password

## 🔐 Upstream keys

Endpoints page → Adds/Edit modal me upstream URL template + upstream key editable hote hain.
Seed values user ke diye hue samples se liye gaye hain (`uersxinfo.in`, `tele-to-phone.felixrdx.xyz`,
`wasifali.biz.id`, `l34k-osint.onrender.com`).

## 📁 Structure

```
osint-hub/
├── app.py              # sab kuch: API, admin, models, logs
├── static/css/style.css
├── static/js/admin.js
├── templates/          # base + dashboard + keys + endpoints + logs + analytics + security + settings + docs + info + landing + login
├── data/               # sqlite db + secret key (auto created)
└── requirements.txt    # sirf Flask
```
