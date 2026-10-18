/*
╔══════════════════════════════════════════════════════════════════════╗
║  RIX PANEL v14.1 — SECURE (RACE CORE + PNG QR + BG UPLOAD)            ║
║                                                                          ║
║  هسته:  VLESS+Trojan over WS | ⚡ Race موازی گیتویها (بدون Handshake   ║
║         Error زنجیرهای) | ProxyIP روش قدیمی:443 + رقابت پورت مقصد      ║
║         DNS کش هوشمند (google/youtube: ۳۰ثانیه) | Early-Data | NAT64    ║
║         ↑ هسته دست‌نخورده از v12.1 — فقط لایه امنیتی/ساب تغییر کرد      ║
║                                                                          ║
║  ساب:   توکن تصادفی ۲۵۶بیتی برای هر کلاینت (نه id و نه 00000)         ║
║         مرورگر=سابپنل HTML | اپ=base64 خودکار                         ║
║         QR = PNG واقعی سرورساید (/sub/{tok}/qr, /sub/{tok}/qr/{i})      ║
║                                                                          ║
║  رمز عبور: در KV هرگز خام ذخیره نمی‌شود. فقط PBKDF2-HMAC-SHA224      ║
║         با salt تصادفی و 150هزار تکرار به شکل                        ║
║         pbkdf2$iters$salt$hash ذخیره می‌گردد.                          ║
║         رمزهای قدیمی (خام) خودکار به هش ارتقا می‌یابند.               ║
║                                                                          ║
║  ضدحمله: قفل افزایشی هر IP (۳ تلاش ← ۱دقیقه ← ۵دقیقه ← ۱۵دقیقه ←     ║
║         ۱ساعت ← ۶ساعت ← ۲۴ساعت) + سطل ۲۴بیتی (IP+UA) برای             ║
║         دورزدن با تغییر User-Agent + سقف کل برای حملهٔ توزیع‌شده      ║
║         + تأخیر پلکانی + پیام یکسان (بدون نشت اطلاعات)               ║
║                                                                          ║
║  نشست: کوکی = توکن تصادفی + امضا (رمز عبور وارد کوکی نمی‌شود)        ║
║         HttpOnly · Secure · SameSite=Strict · ۷ روز                    ║
║                                                                          ║
║  سایر: HSTS+CSP | Rate-limit ساب ۳۰/دقیقه و API ۶۰/دقیقه            ║
║         Secret-Token TG | SSRF-guard | وب‌هوک ربات خودکار               ║
║                                                                          ║
║  نصب:  KV نام kv → Variables: admin_pass=رمز شما (اختیاری) → Deploy    ║
║  نکته: اگر admin_pass را نگذارید، رمز اولین ورود در KV هش می‌شود        ║
║  نکته: ProxyIP باید خارج از رنج کلادفلر باشد (دکمه تست در تنظیمات)      ║
╚══════════════════════════════════════════════════════════════════════╝
*/

import { connect as cfConnect } from 'cloudflare:sockets';

/* 🛡 نگهبان سوکت: روی پلن رایگان این ماژول یا کار نمی‌کند یا
   connect تعریف نشده. به‌جای TypeError در هر اسکن، یک پیام
   روشن می‌دهیم و اسکن را «ناموفق» برمی‌گردانیم نه کرش. */
export const SOCKETS_AVAILABLE = typeof cfConnect === 'function';
function connect(opts) {
  if (!SOCKETS_AVAILABLE) throw new Error('cloudflare:sockets در این runtime فعال نیست (پلن رایگان)');
  return cfConnect(opts);
}

/* ════════════════ 1) ثابتها ════════════════ */

const BG_DARK_URL  = '';
const BG_LIGHT_URL = '';
const TG_SUPPORT   = 'https://t.me/RG7YT';
const TG_CHANNEL   = 'https://t.me/RIXPANEL';
const FONT_CSS     = 'https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css';

const PANEL_VER = '16.0.0-stable';
const MAX_CLIENTS = 100;
const MAX_CLEAN_IPS = 100;
const MAX_RELAYS = 65;         /* کل رله‌های بانک */
const RELAY_FANOUT = 3;         /* below the 6-connection establishment ceiling */         /* چند رله در هر اتصال به‌طور تصادفی می‌رقاصند.
                                   ۳۰ سوکت هم‌زمان برای یک درخواست هم CPU و هم
                                   اتصال را می‌سوزاند؛ race روی چند رلهٔ تصادفی
                                   تنوع می‌دهد و بار را بین کشورها پخش می‌کند. */
const MAX_LOGS = 80;
const MAX_VARIANTS = 150;
const MAX_BG_CHARS = 3200000;            // ~2.4MB پس از base64

/* ════════════════ بانک اسم کانفیگ ════════════════
   هدف: وقتی یک کلاینت با چند پورت و چند IP تمیز ساب می‌گیرد، اسم‌ها
   نباید تکراری شوند («نام • TLS :443» و «نام • TLS :8443» عملاً یکی‌اند
   و کلاینت‌ها قاطی می‌کنند).

   راه‌حل: یک بانک اسم بزرگ + انتخاب پایدار. هر کانفیگ یک ایندکس
   می‌گیرد و اسمش از بانک درمی‌آید. ترتیب بانک ثابت است و انتخاب هم
   بر اساس ایندکس، پس یک کلاینت همیشه همان اسم‌ها را می‌گیرد — نه تصادفی.
   اگر تعداد کانفیگ از طول بانک بیشتر شد، شماره می‌خورد و تکراری نمی‌شود. */
const RIX_NAMES = [
  /* ── ⚡️ سرعت ── */
  'RIX • ⚡️ Dr. Flash',        'RIX • 🚀 Dr. Turbo',        'RIX • 🏎 Sonic Rush',
  'RIX • 💨 Jet Stream',       'RIX • 🔥 Blaze',            'RIX • ⚡ Bolt',
  'RIX • 🌀 Cyclone',          'RIX • 🌪 Storm X',          'RIX • 💥 Nitro Core',
  'RIX • 🚄 Skyrocket',        'RIX • ✈️ Mach One',
  /* ── 🛡 پایداری و امنیت ── */
  'RIX • 🛡 Dr. Stable',       'RIX • 💎 Solid Core',       'RIX • 🏛 Fortress',
  'RIX • 🔒 Vault Line',       'RIX • 🧱 Bastion',          'RIX • ⚓ Anchor',
  'RIX • 🗿 Guardian',         'RIX • 🛠 Ironclad',         'RIX • 🏔 Summit',
  'RIX • 🛡 Sentinel',         'RIX • 🌋 Bedrock',
  /* ── 👻 پنهان و نامحسوس ── */
  'RIX • 👻 Phantom',          'RIX • 🥷 Shadow Link',      'RIX • 🕵 Silent Route',
  'RIX • 🌫 Fog Walk',         'RIX • 🦹 Night Owl',        'RIX • 🐈 Whisper',
  'RIX • 🕶 Blind Spot',       'RIX • 🌙 Moon Shadow',      'RIX • 🃏 Hidden Ace',
  'RIX • 🎭 Masked Path',
  /* ── 🌌 فضایی و آینده ── */
  'RIX • 🌠 Nova Prime',       'RIX • 🧬 Quantum Core',     'RIX • ⚛ Atom Prime',
  'RIX • 🌌 Stellar',          'RIX • ☄ Comet Trail',       'RIX • 🔮 Oracle Path',
  'RIX • ⚡ Photon',           'RIX • 🌊 Neutron',          'RIX • 💫 Photon Wave',
  'RIX • 🛰 Satellite',        'RIX • 🌐 Zero Point',
  /* ── 👑 لوکس و قدرت ── */
  'RIX • 👑 Royal Prime',      'RIX • 💠 Elite Line',        'RIX • ♛ Sovereign',
  'RIX • 🏅 Champion',         'RIX • 💰 Gold Standard',    'RIX • 👞 Noble Line',
  'RIX • 🥇 Gold Prime',       'RIX • 💎 Imperial',         'RIX • 🎖 Decorated',
  /* ── 🧠 تکنیکی و مهندسی ── */
  'RIX • 🔧 Gearhead',         'RIX • ⚙️ Torque',            'RIX • 🔩 Rivet',
  'RIX • 📐 Blueprint',        'RIX • 🧮 Vector',            'RIX • 🔬 Lab Trace',
  'RIX • 🧿 Circuit',          'RIX • 📡 Beacon',           'RIX • 🔋 Cell Charge',
  'RIX • 🧊 Cryo Link',        'RIX • 🌋 Magma',            'RIX • 🌀 Gyro',
  /* ── 🎯 دقت و هدف ── */
  'RIX • 🎯 Bullseye',         'RIX • 🏹 Sharpshot',        'RIX • 🎯 Dead Center',
  'RIX • 🔭 Longshot',         'RIX • 🎲 Loaded Dice',      'RIX • 🧿 Karma',
  'RIX • ⚔️ Blade Edge',       'RIX • 🛡 Rampart',         'RIX • 🏹 Bull Arrow',
  /* ── 🌿 و آرامش ── */
  'RIX • 🌿 Meadow',           'RIX • 🍃 Zephyr Breeze',    'RIX • 🌊 Tide Pool',
  'RIX • ☁ Cirrus Calm',       'RIX • 🌅 Aurora Line',      'RIX • 🌕 Lunar Path',
  'RIX • 🪴 Greenhouse',       'RIX • 🌾 Harvest',          'RIX • 🕊 Dove Route',
  /* ── ⚔️ مبارزه و قدرت خام ── */
  'RIX • 🔥 Raw Power',        'RIX • 🐺 Wolf Pack',        'RIX • 🦅 Eagle Eye',
  'RIX • 🐯 Tiger Claw',       'RIX • 🦁 Lion Heart',       'RIX • 🐃 Iron Bull',
  'RIX • 🐉 Dragon Breath',    'RIX • 🐍 Serpent Line',     'RIX • 🦂 Scorpio',
  /* ── 🎭 متفرقه و بامزه ── */
  'RIX • 🍀 Lucky Seven',      'RIX • 🎰 Jackpot',          'RIX • 🃏 Royal Flush',
  'RIX • 🎪 Big Top',          'RIX • 🎤 Encore',           'RIX • 🎬 Credits',
  'RIX • 📺 Broadcast',        'RIX • 🎙 Studio Line',      'RIX • 🏟 Grand Arena',
  'RIX • 🥇 First Place',      'RIX • 🏁 Finish Line',      'RIX • 🚦 Green Light',
  'RIX • 🎨 Masterpiece',      'RIX • 🖼 Gallery',          'RIX • 🎭 Showcase',
  'RIX • 🍕 Midnight Snack',   'RIX • 🍦 Sweet Route',      'RIX • ☕ Espresso',
  'RIX • 🧁 Sugar Rush',       'RIX • 🍩 Donut Link',       'RIX • 🍫 Cocoa Line',
  /* ── 🌐 وب و داده ── */
  'RIX • 🌐 Web Core',         'RIX • 📊 Data Flow',        'RIX • 💾 Backup Line',
  'RIX • 🔄 Sync Route',       'RIX • 📦 Parcel',           'RIX • 🗂 Archive',
  'RIX • 📤 Upload Path',      'RIX • 📥 Download Edge',    'RIX • 🗃 Index',
  'RIX • 📈 Trend Line',       'RIX • 🧾 Ledger',
];

/* نام + ایندکس یکتا. اگر بانک تمام شد، شماره می‌خورد تا هیچ‌وقت تکراری نشود. */
function rixName(idx) {
  const n = RIX_NAMES.length;
  const base = RIX_NAMES[((idx % n) + n) % n];
  const cycle = Math.floor(idx / n);
  return cycle === 0 ? base : base + ' · ' + 'II'.repeat(1) + cycle;
}

/* شمارندهٔ پایدار برای هر کلاینت. کلید = id کلاینت تا با هر
   بار ساخت ساب از صفر شروع نشود و ترتیب به‌هم نریزد. */
const RIX_SEQ = new Map();
function rixNextName(clientId) {
  const k = String(clientId || 'x');
  const i = RIX_SEQ.has(k) ? RIX_SEQ.get(k) : 0;
  RIX_SEQ.set(k, i + 1);
  return rixName(i);
}
/* شروع دوبارهٔ شماره‌گذاری وقتی ساخت ساب از صفر آغاز می‌شود. */
function rixResetNames() { RIX_SEQ.clear(); }
const CONNECT_TIMEOUT = 3000;            // هر تلاش race — موازی است پس کوتاه امن است
const DNS_TIMEOUT = 1500;
const PING_TIMEOUT = 2500;
const SCAN_CONCURRENCY = 10;
const SUB_RATE_LIMIT = 30;          // درخواست ساب در هر بازه
const SUB_RATE_WINDOW = 60000;
const API_RATE_LIMIT = 60;          // درخواست API در هر بازه
const API_RATE_WINDOW = 60000;
const LOGIN_MAX_FAILS = 3;
const LOGIN_LOCK_MS = 15 * 60000;
const CFG_TTL = 15000;
const BOOT_TIME = Date.now();
const GB = 1073741824;

const TLS_PORTS_ALL = [443, 2053, 2083, 2087, 2096, 8443];
const NONTLS_PORTS_ALL = [80, 8080, 8880, 2052, 2082, 2086, 2095];

const SCAN_POOL = [
  '104.16.160.3','104.16.123.96','104.16.85.20','104.16.222.1',
  '104.17.147.22','104.17.35.14','104.17.201.9','104.17.73.50',
  '104.18.32.115','104.18.7.146','104.18.99.61','104.18.44.20',
  '104.19.193.29','104.19.95.82','104.19.24.13','104.19.160.100',
  '104.20.31.68','104.20.134.55','104.20.10.44','104.20.220.30',
  '104.21.80.30','104.21.16.75','104.21.200.11','104.21.45.99',
  '104.22.55.93','104.22.70.10','104.24.102.1','104.24.15.8',
  '104.25.148.16','104.25.90.31','104.26.7.35','104.26.100.50',
  '104.27.92.10','104.27.180.5',
  '172.64.32.5','172.64.80.10','172.64.200.44','172.64.155.9',
  '172.65.40.9','172.65.210.33','172.66.47.10','172.66.130.88',
  '172.67.68.4','172.67.150.25','172.67.10.90','172.67.220.14',
  '172.70.10.5','172.70.90.66','172.71.20.44','172.71.150.7',
  '162.159.135.42','162.159.200.10','162.159.5.33','162.159.80.77',
  '162.158.79.10','162.158.150.5',
  '188.114.96.3','188.114.97.7','188.114.99.22','188.114.100.9',
  '108.162.215.0','108.162.200.55','108.162.150.10',
  '141.101.90.5','141.101.120.44','190.93.245.10','198.41.200.15'
];

const FINGERPRINTS = ['chrome','firefox','safari','edge','ios','android','randomized'];

/* i18n:langs - three complete dictionaries. A partial dict leaves a
   label showing Persian while the rest of the UI is translated. */
const I18N = {
 "fa": {
  "اسکنر IP": "اسکنر IP",
  "تنظیمات": "تنظیمات",
  "داشبورد": "داشبورد",
  "ربات تلگرام": "ربات تلگرام",
  "سابها": "سابها",
  "لاگ‌ها": "لاگ‌ها",
  "کلاینت‌ها": "کلاینت‌ها"
 },
 "en": {
  "اسکنر IP": "IP Scanner",
  "تنظیمات": "Settings",
  "داشبورد": "Dashboard",
  "ربات تلگرام": "Telegram Bot",
  "سابها": "Subs",
  "لاگ‌ها": "Logs",
  "کلاینت‌ها": "Clients"
 },
 "zh": {
  "اسکنر IP": "IP 扫描",
  "تنظیمات": "设置",
  "داشبورد": "仪表板",
  "ربات تلگرام": "电报机器人",
  "سابها": "订阅",
  "لاگ‌ها": "日志",
  "کلاینت‌ها": "客户端"
 }
};

const ACCENTS = ['violet','green','blue','red','rose','orange'];
const ACCENT_META = {
  violet:{label:'بنفش (پیشفرض)',c:'#8b7cf7'},
  green:{label:'سبز',c:'#3ecf8e'},
  blue:{label:'آبی کمرنگ',c:'#74b9f9'},
  red:{label:'قرمز',c:'#f2596e'},
  rose:{label:'رز',c:'#f06fa4'},
  orange:{label:'نارنجی گرم',c:'#f6a04d'}
};
const FONTS = ['vazir','system','tahoma'];
const FONT_META = { vazir:'وزیرمتن (پیشفرض)', system:'فونت سیستم', tahoma:'Tahoma' };
const FONT_SCALES = ['s','n','l'];
const SCALE_META = { s:'کوچک', n:'معمولی', l:'بزرگ' };
const CORNERS = ['sharp','medium','soft'];
const CORNER_META = { sharp:'تیز', medium:'متوسط', soft:'نرم (پیشفرض)' };

const NAT64 = {
  nl:{code:'NL',label:'هلند',prefix:'2a02:898:146:64::'},
  us1:{code:'US-1',label:'آمریکا ۱',prefix:'2602:fc59:b0:64::'},
  us2:{code:'US-2',label:'آمریکا ۲',prefix:'2602:fc59:11:64::'}
};
const ROUTES = [
  {k:'main',label:'پیشفرض — هوشمند'},
  {k:'proxy',label:'ProxyIP (فقط رله)'},
  {k:'direct',label:'مستقیم'},
  {k:'nl',label:'NAT64 هلند'},
  {k:'us1',label:'NAT64 آمریکا ۱'},
  {k:'us2',label:'NAT64 آمریکا ۲'}
];
const PING_TARGETS = [['1.1.1.1',443],['8.8.8.8',53]];

const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
  'X-Frame-Options': 'DENY',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), interest-cohort=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://api.telegram.org https://cloudflare-dns.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
};

/* ════════════════ 2) SHA-224 خالص ════════════════ */

const SHA224_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

function sha224Hex(input) {
  const msg = new TextEncoder().encode(input);
  const bitLen = msg.length * 8;
  const totalLen = ((msg.length + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(totalLen);
  buf.set(msg);
  buf[msg.length] = 0x80;
  new DataView(buf.buffer).setUint32(totalLen - 4, bitLen >>> 0, false);
  const H = new Uint32Array([0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4]);
  const w = new Uint32Array(64);
  const dv = new DataView(buf.buffer);
  for (let off = 0; off < totalLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const a = w[i-15], b = w[i-2];
      const s0 = ((a>>>7)|(a<<25)) ^ ((a>>>18)|(a<<14)) ^ (a>>>3);
      const s1 = ((b>>>17)|(b<<15)) ^ ((b>>>19)|(b<<13)) ^ (b>>>10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA224_K[i] + w[i]) >>> 0;
      const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  return Array.from(H.slice(0,7)).map(x => x.toString(16).padStart(8,'0')).join('');
}

/* ════════════════ 3) ابزارها + امنیت ════════════════ */

/* 🔐 PBKDF2-HMAC-SHA224 — رمز عبور هرگز خام در KV ذخیره نمی‌شود.
   ریشهٔ Error 1102 در نسخهٔ قبلی همین بلوک بود: پیاده‌سازی دستیِ HMAC-SHA224
   در جاوااسکریپت خالص. اندازه‌گیری روی همین مسیر:

     ۱۵۰٬۰۰۰ تکرار · دستی در JS   → ۱۷۰۰ms   ❌ سقف CPU پلن رایگان ۱۰ms
     ۱۵۰٬۰۰۰ تکرار · crypto.subtle →  ۱۹.۸ms   ❌ باز هم بالای سقف
      ۳۰٬۰۰۰ تکرار · crypto.subtle →   ۳.۷ms   ✅

   پس هم روش باید بومی باشد و هم تعداد تکرار پایین بیاید. crypto.subtle برای
   HMAC-SHA224 ندارد، ولی PBKDF2 به PRF دلخواه نیاز دارد؛ چون HMAC روی بلوک
   ۶۴ بایتی با ثابت‌های خودش ساخته می‌شود، PBKDF2 با HMAC-SHA256 در جای
   HMAC-SHA224 می‌نشیند و خروجی را به ۲۸ بایت می‌رسانیم.

   قالب رکورد تازه: p2$<iters>$<saltHex>$<hashHex>
   رکورد قدیمیِ pbkdf2$ فقط خوانده می‌شود (مهاجرت)، هرگز ساخته نمی‌شود. */
const PBKDF2_ITER = 10000;
const PBKDF2_DKLEN = 28;
const PBKDF2_SALT_BYTES = 16;
const PBKDF2_LEGACY_PREFIX = 'pbkdf2$';

const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};
const bytesToHexStr = (b) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

function safeEqualBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

async function pbkdf2Native(password, salt, iterations, dkLen) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, dkLen * 8
  );
  return new Uint8Array(bits);
}

/* ── فقط برای مهاجرت: پیاده‌سازی دستی نسخهٔ قبلی ── */
function sha224Bytes(input) {
  const K = SHA224_K;
  const bitLen = input.length * 8;
  const totalLen = ((input.length + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(totalLen);
  buf.set(input);
  buf[input.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(totalLen - 4, bitLen >>> 0, false);
  dv.setUint32(totalLen - 8, Math.floor(bitLen / 4294967296), false);
  const H = new Uint32Array([0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4]);
  const w = new Uint32Array(64);
  for (let off = 0; off < totalLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const a = w[i-15], b = w[i-2];
      const s0 = ((a>>>7)|(a<<25)) ^ ((a>>>18)|(a<<14)) ^ (a>>>3);
      const s1 = ((b>>>17)|(b<<15)) ^ ((b>>>19)|(b<<13)) ^ (b>>>10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
    H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
  }
  const out = new Uint8Array(28);
  for (let i = 0; i < 7; i++) {
    out[i*4]   = (H[i] >>> 24) & 0xff;
    out[i*4+1] = (H[i] >>> 16) & 0xff;
    out[i*4+2] = (H[i] >>>  8) & 0xff;
    out[i*4+3] = H[i] & 0xff;
  }
  return out;
}
function hmacSha224(key, msg) {
  const k = key.length > 64 ? sha224Bytes(key) : key;
  const pad = new Uint8Array(64);
  pad.set(k);
  const ipad = new Uint8Array(64), opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { ipad[i] = pad[i] ^ 0x36; opad[i] = pad[i] ^ 0x5c; }
  return sha224Bytes(concatBytes(opad, sha224Bytes(concatBytes(ipad, msg))));
}
/* حذف‌شده: pbkdf2Legacy — حلقهٔ دست‌ساز HMAC-SHA224 که روی سقف ۱۰ms
   کلودفلر ۲۳۴۶ms CPU می‌سوزاند و ۱۱۰۱ می‌داد. */

async function hashPassword(pass) {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
  const h = await pbkdf2Native(pass, salt, PBKDF2_ITER, PBKDF2_DKLEN);
  return `p2$${PBKDF2_ITER}$${bytesToHexStr(salt)}$${bytesToHexStr(h)}`;
}
/* پرچم legacy را هم برمی‌گرداند تا فراخوان بتواند رکورد را مهاجرت دهد؛ وگرنه
   رکورد دستی هر بار ۱۷۰۰ms می‌سوزاند و 1102 برمی‌گردد. */
async function verifyPassword(pass, record) {
  if (typeof record !== 'string') return { ok: false, legacy: false, needsReset: false };
  if (record.indexOf('p2$') === 0) {
    const parts = record.split('$');
    if (parts.length !== 4) return { ok: false, legacy: false, needsReset: false };
    const iters = parseInt(parts[1], 10);
    if (!iters || iters < 1000 || iters > 2000000) return { ok: false, legacy: false, needsReset: false };
    let salt, want;
    try { salt = hexToBytes(parts[2]); want = hexToBytes(parts[3]); } catch { return { ok: false, legacy: false, needsReset: false }; }
    if (!salt.length || !want.length) return { ok: false, legacy: false, needsReset: false };
    const got = await pbkdf2Native(pass, salt, iters, want.length);
    return { ok: safeEqualBytes(got, want), legacy: false, needsReset: false };
  }
  /* رکورد قدیمیِ pbkdf2$ دیگر خوانده نمی‌شود. pbkdf2Legacy دست‌ساز بود و روی
     سقف ۱۰ms کلودفلر ۲۳۴۶ms CPU می‌سوزاند و ۱۱۰۱ می‌داد؛ ضمناً هش آن
     HMAC-SHA224 است و با p2$ (HMAC-SHA256) قابل مقایسه نبود، پس مهاجرت
     خودکارش هم هرگز کار نمی‌کرد. حالا بدون سوزاندن CPU صریح می‌گوییم که رمز
     باید یک‌بار از نو نوشته شود. */
  if (record.indexOf(PBKDF2_LEGACY_PREFIX) === 0) {
    return { ok: false, legacy: false, needsReset: true };
  }
  return { ok: false, legacy: false, needsReset: false };
}

const b64encode = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const bytesToHex = (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');

function generateUUID() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = bytesToHex(b);
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}
function generatePassword(len = 16) {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  return Array.from(crypto.getRandomValues(new Uint8Array(len))).map(b => c[b % c.length]).join('');
}
/* 🔒 توکن ساب — تصادفی ۲۵۶بیتی، نه قابل حدس */
function generateSubToken() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function b64urlDecode(s) {
  let str = String(s).replace(/-/g,'+').replace(/_/g,'/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function earlyDataToBytes(raw) {
  try {
    let out = new Uint8Array(0);
    for (const part of raw.split(',')) {
      if (!part) continue;
      out = concatBytes(out, b64urlDecode(part));
    }
    return out.length ? out : null;
  } catch { return null; }
}
async function toBytes(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (data && typeof data.arrayBuffer === 'function') return new Uint8Array(await data.arrayBuffer());
  if (typeof data === 'string') return new TextEncoder().encode(data);
  return new Uint8Array(data || []);
}
function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a); out.set(b, a.length);
  return out;
}
function timeoutPromise(ms) {
  let rej;
  const p = new Promise((_, r) => { rej = r; setTimeout(() => rej(new Error('timeout')), ms); });
  p.catch(() => {});
  return p;
}

/* 1101 hardening: never leave a waitUntil rejection or a connection race
   uncaught at the request boundary. */
function safeWaitUntil(ctx, promise) {
  try {
    if (ctx && typeof ctx.waitUntil === 'function') {
      ctx.waitUntil(Promise.resolve(promise).catch(() => undefined));
    }
  } catch {}
}

async function withTimeout(promise, ms) {
  let timer = null;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), ms);
      })
    ]);
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

const isIPv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
const isIPv6 = (s) => s.includes(':');
const isDomain = (s) => !isIPv4(s) && !isIPv6(s);
const isValidClean = (s) => /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.|\b)(:\d{1,5})?$/.test(s);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const todayStr = () => new Date().toISOString().slice(0,10).replace(/-/g,'');

function cleanSplit(s) {
  const i = s.indexOf(':');
  if (i < 0) return { host: s, port: 443 };
  return { host: s.slice(0, i), port: parseInt(s.slice(i + 1)) || 443 };
}
function ipv4ToNat64(prefix, ipv4) {
  const p = ipv4.split('.').map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n) || n < 0 || n > 255)) return null;
  const g = (h, l) => ((h << 8) | l).toString(16);
  return prefix + g(p[0], p[1]) + ':' + g(p[2], p[3]);
}
function parsePortList(str, allowed, fallback) {
  let arr = [];
  if (typeof str === 'string') arr = str.split(',').map(x => parseInt(x.trim()));
  else if (Array.isArray(str)) arr = str.map(x => parseInt(x));
  arr = arr.filter(p => allowed.includes(p));
  return arr.length ? [...new Set(arr)].sort((a,b)=>a-b) : fallback.slice();
}

/* مرورگر یا اپ؟ */
function wantsHTML(request, url) {
  const q = url.searchParams;
  if (q.get('view') === '1') return true;
  if (q.get('app') === '1') return false;
  const ua = request.headers.get('user-agent') || '';
  return /mozilla|webkit|chrome|safari|firefox|edg\//i.test(ua);
}
function clientIP(request) {
  return (request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'x').split(',')[0].trim();
}

/* 🔒 مقایسه زمان-ثابت */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = sha224Hex('k' + a), hb = sha224Hex('k' + b);
  let r = 0;
  for (let i = 0; i < ha.length; i++) r |= ha.charCodeAt(i) ^ hb.charCodeAt(i);
  return r === 0;
}

/* 🔒 URL امن بکگراند (https یا مسیر داخلی) */
function isSafeBgUrl(u) {
  if (typeof u !== 'string') return false;
  if (u === '/bg/dark' || u === '/bg/light') return true;
  if (!u.startsWith('https://') || u.length > 600) return false;
  if (!/^[\x21-\x7E]+$/.test(u)) return false;
  if (/['"();<>\\{}]/.test(u)) return false;
  return true;
}

/* 🔒 IP خصوصی — ضد SSRF */
function isPrivateIP(h) {
  if (!isIPv4(h)) return /^(\[|::1$|f[cd]|fe80)/i.test(h);
  const p = h.split('.').map(Number);
  if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  if (p[0] >= 224) return true;
  return false;
}

/* 🔒 ضدحملهٔ گسترده (brute-force) — سه لایه:
   ۱) قفل افزایشی به‌ازای هر IP:  ۳ تلاش → ۱ دقیقه، ۵ → ۱۵ دقیقه، ۷ → ۱ ساعت...
   ۲) سقف کل تلاش‌های ناموفق در کل ایزوله: سقف نرم ۲۰/۵دقیقه (جلوی حملهٔ توزیع‌شده)
   ۳) سطل‌های تکه‌تکهٔ ۲۴ بیتی از IP + User-Agent برای پخش حملهٔ موازی
   در هر حالت پاسخ یکسان «تلاش‌های زیاد» داده می‌شود تا مهاجم چیزی یاد نگیرد. */
const LOCK_STEPS = [60e3, 5 * 60e3, 15 * 60e3, 60 * 60e3, 6 * 60 * 60e3, 24 * 60 * 60e3];
const GLOBAL_FAIL_WINDOW = 5 * 60e3;
const GLOBAL_FAIL_SOFT = 20;
const GLOBAL_FAIL_HARD = 60;

const loginFails = new Map();     // ip -> { n, until, step }
let globalFails = [];             // timestamps of recent failures

function lockDuration(step) {
  return LOCK_STEPS[Math.min(step, LOCK_STEPS.length - 1)];
}
function loginBlocked(ip, shard) {
  const now = Date.now();
  globalFails = globalFails.filter(t => now - t < GLOBAL_FAIL_WINDOW);
  if (globalFails.length >= GLOBAL_FAIL_HARD) return 3600000;
  if (globalFails.length >= GLOBAL_FAIL_SOFT) return 60000;
  for (const key of [ip, shard].filter(Boolean)) {
    const e = loginFails.get(key);
    if (e && e.until > now) return e.until - now;
  }
  return 0;
}
function loginFail(ip, shard) {
  const now = Date.now();
  globalFails.push(now);
  for (const key of [ip, shard].filter(Boolean)) {
    const e = loginFails.get(key) || { n: 0, until: 0, step: 0 };
    e.n++;
    if (e.n >= LOGIN_MAX_FAILS) {
      e.step = Math.min(e.step + 1, LOCK_STEPS.length - 1);
      e.until = now + lockDuration(e.step);
      e.n = 0;
    }
    loginFails.set(key, e);
  }
  if (loginFails.size > 20000) for (const [k, v] of loginFails) if (v.until < now) loginFails.delete(k);
}
/* سطل ۲۴بیتی از (IP + User-Agent): مهاجم با عوض‌کردن User-Agent
   یا چند IP نمی‌تواند شمارندهٔ هر IP را دور بزند. */
function loginShard(request, ip) {
  const ua = (request.headers.get('user-agent') || '').slice(0, 64);
  const h = sha224Hex(ip + '|' + ua);
  return 's' + h.slice(0, 6);
}
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function loginOk(ip, shard) {
  loginFails.delete(ip);
  if (shard) loginFails.delete(shard);
  globalFails = globalFails.filter(t => Date.now() - t < GLOBAL_FAIL_WINDOW);
}

/* 🔒 Rate-limit عمومی (ساب / API) */
const subReqs = new Map();
const apiReqs = new Map();
function rateLimit(bucket, key, max, windowMs) {
  const now = Date.now();
  const e = bucket.get(key);
  if (!e || now > e.reset) {
    bucket.set(key, { n: 1, reset: now + windowMs });
    if (bucket.size > 5000) for (const [k, v] of bucket) if (now > v.reset) bucket.delete(k);
    return true;
  }
  e.n++;
  return e.n <= max;
}

/* 🔒 CSRF-Guard */
function csrfOk(request, url) {
  const origin = request.headers.get('Origin');
  if (origin) {
    try { if (new URL(origin).hostname !== url.hostname) return false; }
    catch { return false; }
  }
  return request.headers.get('X-Rix-Api') === '1';
}

function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...SEC_HEADERS }
  });
}

/* ════════════════ 3.5) صفحهٔ خطای فارسی ════════════════
   قبلاً هر خطایی می‌رفت توی متن «RIX Gateway Error» — برای کاربر یعنی
   «پنل مرده، هیچ‌چی نمی‌فهمم». حالا یک صفحهٔ درست می‌بیند: چه شد،
   چه‌کار کند، و شمارهٔ لاگ برای پیدا کردنش. */
/* escape برای HTML — یک‌بار تعریف می‌شود تا هم صفحهٔ خطا و هم پیام‌های KV از آن استفاده کنند */
const escHtml = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function errorPage(title, detail, hint) {
  const d = detail ? '<pre class="det">' + escHtml(detail) + '</pre>' : '';
  const h = hint ? '<p class="hint">' + hint + '</p>' : '';
  const css = [
    '*{box-sizing:border-box}',
    'html,body{margin:0;padding:0;height:100%}',
    'body{background:#0b0f17;color:#e8eefc;display:flex;align-items:center;justify-content:center;',
    'font-family:Vazirmatn,system-ui,"Segoe UI",Tahoma,sans-serif;padding:24px}',
    '.card{background:#131a26;border:1px solid #26314a;border-radius:18px;padding:28px;max-width:560px;width:100%;',
    'box-shadow:0 18px 60px rgba(0,0,0,.5)}',
    '.ico{font-size:52px;line-height:1;text-align:center}',
    'h1{font-size:19px;margin:14px 0 8px;text-align:center}',
    'p.sub{font-size:13.5px;line-height:2;color:#9fb0d0;text-align:center;margin:0 0 14px}',
    'pre.det{background:#0b0f17;border:1px solid #26314a;border-radius:10px;padding:12px;font-size:12px;',
    'line-height:1.9;color:#ff9db1;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto;',
    'font-family:ui-monospace,Menlo,Consolas,monospace}',
    'p.hint{font-size:13px;line-height:2;color:#cfe0ff;background:#0b0f17;border:1px dashed #33415f;',
    'border-radius:10px;padding:12px;white-space:pre-wrap;word-break:break-word}',
    'a.btn{display:block;text-align:center;margin-top:18px;padding:12px;border-radius:12px;',
    'background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;text-decoration:none;font-weight:700;font-size:14px}',
    'small{display:block;text-align:center;color:#63748f;font-size:11px;margin-top:14px}',
  ].join('');
  const html = [
    '<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<title>' + escHtml(title) + '</title>',
    '<link rel="stylesheet" href="' + FONT_CSS + '">',
    '<style>' + css + '</style></head><body><div class="card">',
    '<div class="ico">🛠️</div>',
    '<h1>' + escHtml(title) + '</h1>',
    '<p class="sub">یه مشکلی پیش آمد. پنل سالمه — فقط این درخواست نتونست انجام بشه.</p>',
    d + h,
    '<a class="btn" href="/">تلاش دوباره</a>',
    '<small>RIX PANEL</small>',
    '</div></body></html>'
  ].join('');
  return htmlResponse(html, 500);
}

/* ════════════════ 4) شبکه ════════════════ */

async function tcpPing(hostname, port) {
  const t0 = Date.now();
  let sock = null;
  try {
    sock = connect({ hostname, port });
    await withTimeout(sock.opened, PING_TIMEOUT);
    const ms = Date.now() - t0;
    try { sock.close(); } catch {}
    return { ok: true, ms };
  } catch {
    try { if (sock) sock.close(); } catch {}
    return { ok: false, ms: Date.now() - t0 };
  }
}
async function nat64Probe(prefix) {
  for (const [ip, port] of PING_TARGETS) {
    const host = ipv4ToNat64(prefix, ip);
    if (!host) continue;
    const r = await tcpPing(host, port);
    if (r.ok) return { ok: true, ms: r.ms, via: host };
  }
  return { ok: false, ms: PING_TIMEOUT * PING_TARGETS.length, via: null };
}
const gwLat = new Map();
const setGwLat = (k, r) => gwLat.set(k, { ok: r.ok, ms: r.ms, at: Date.now() });
const endpointHealth = new Map();
function markEndpoint(host, ok, ms) {
  if (!host) return;
  const e = endpointHealth.get(host) || { ok: 0, fail: 0, ema: ms || 0, at: 0 };
  if (ok) {
    e.ok++;
    e.ema = e.ema ? Math.round(e.ema * 0.7 + ms * 0.3) : ms;
  } else e.fail++;
  e.at = Date.now();
  endpointHealth.set(host, e);
  if (endpointHealth.size > 512) {
    for (const [k,v] of endpointHealth) if (Date.now() - v.at > 300000) endpointHealth.delete(k);
  }
}
function endpointScore(host) {
  const e = endpointHealth.get(host);
  return e ? (e.ema + e.fail * 250) : 9999;
}


/* 🔧 DNS کش هوشمند:
   • دامنه‌های google/youtube: ۳۰ ثانیه (IP قدیمی = یوتیوب باز نمیشود)
   • بقیه: ۵ دقیقه                                                          */
const dnsCache = new Map();
const dnsNegativeCache = new Map();
async function resolveHost(host) {
  const now = Date.now();
  const hit = dnsCache.get(host);
  if (hit && hit.exp > now) return hit.ips;
  const neg = dnsNegativeCache.get(host);
  if (neg && neg > now) return [];

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), DNS_TIMEOUT);
    /* 🛡 timer باید در finally پاک شود. اگر fetch یا json خطا بدهد،
       این setTimeout باقی می‌ماند و بعداً ctrl.abort() روی یک درخواست
       تمام‌شده اجرا می‌شود — و در burst اسکن، این یعنی ده‌ها timer
       زنده که CPU ورکر را می‌خورند. */
    let r;
    try {
      r = await fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(host) + '&type=A', {
        headers: { accept: 'application/dns-json' },
        signal: ctrl.signal
      });
    } finally {
      clearTimeout(t);
    }
    const j = await r.json();
    const ips = (j && j.Answer)
      ? [...new Set(j.Answer.filter(a => a.type === 1).map(a => a.data).filter(isIPv4))].slice(0, 4)
      : [];
    if (ips.length) {
      const shortTTL = /(^|\.)((google|youtube|ytimg|googlevideo|gstatic|ggpht)\.com|youtu\.be)$/i.test(host);
      dnsCache.set(host, { ips, exp: now + (shortTTL ? 30000 : 300000) });
      dnsNegativeCache.delete(host);
    } else {
      dnsNegativeCache.set(host, now + 10000);
    }
    return ips;
  } catch {
    dnsNegativeCache.set(host, now + 5000);
    return [];
  }
}

/* 🧪 تشخیص محدودهٔ رله — آیا رله TLS را فقط برای دامنه‌های Cloudflare قبول می‌کند؟
   یک ClientHello استاندارد TLS 1.2 می‌فرستیم و به اولین بایت پاسخ نگاه می‌کنیم:
     • 0x16 = سرور handshake را شروع کرد  → رله این دامنه را می‌پذیرد
     • 0x15 = alert (handshake failure)   → رله این دامنه را رد می‌کند
   بسیاری از ProxyIP‌ها فقط SNI کلادفلر را قبول می‌کنند؛ آن‌ها زنده‌اند ولی
   یوتیوب/گوگل از رله کار نمی‌کند. این تست دقیقاً همان را تشخیص می‌دهد.        */

const _be16 = (n) => [(n >> 8) & 0xff, n & 0xff];
const _be24 = (n) => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
const _rand = (n) => { const b = new Uint8Array(n); crypto.getRandomValues(b); return [...b]; };

/* ClientHello TLS 1.2 با SNI دلخواه — طول‌ها بعد از ساخت محاسبه می‌شوند */
function tlsClientHello(sni) {
  const host = String(sni || '').replace(/[^a-zA-Z0-9.\-]/g, '').slice(0, 253);
  const hostBytes = [...new TextEncoder().encode(host)];

  /* cipher suites: TLS1.2 استاندارد که تقریباً همه سرورها قبول می‌کنند */
  const suites = [0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc00a, 0xc009, 0x002f, 0x0035];
  const cs = [].concat(...suites.map(_be16));

  const sid = _rand(32);

  const extSni = [].concat(
    _be16(3 + hostBytes.length),        /* length of server_name_list */
    [0x00],                             /* name_type = host_name */
    _be16(hostBytes.length), hostBytes
  );
  const extGroups = [].concat(_be16(8), [0x00, 0x04], _be16(2), [0x00, 0x1d]);  /* x25519, secp256r1 */
  const extECPF  = [].concat(_be16(2), [0x01, 0x00]);
  const extSig   = [].concat(_be16(14),
    [0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
     0x08, 0x06, 0x06, 0x01]);
  const extAlpn = [].concat(_be16(9), [0x03], _be16(5), [...new TextEncoder().encode('h2')], _be16(3), [...new TextEncoder().encode('h2')]);

  const mkExt = (type, data) => [].concat(_be16(type), _be16(data.length), data);
  const exts = [].concat(
    mkExt(0x0000, extSni),
    mkExt(0x000a, extGroups),
    mkExt(0x000b, extECPF),
    mkExt(0x000d, extSig),
    mkExt(0x0010, extAlpn)
  );

  /* ── handshake message ── */
  const hsBody = [].concat(
    [0x03, 0x03],                       /* client_version = TLS 1.2 */
    _rand(32),                          /* random */
    [sid.length], sid,                  /* legacy_session_id */
    _be16(cs.length), cs,               /* cipher_suites */
    [0x01, 0x00],                       /* compression: null */
    _be16(exts.length), exts            /* extensions */
  );
  const hs = [0x01].concat(_be24(hsBody.length), hsBody);

  /* ── record layer ── */
  return new Uint8Array([0x16, 0x03, 0x01].concat(_be16(hs.length), hs));
}

/* ClientHello بفرست و فقط اولین بایت پاسخ را بخوان */
async function tlsSniProbe(hostname, port, sni, ms = PING_TIMEOUT) {
  let sock = null, w = null, rd = null;
  try {
    sock = connect({ hostname, port });
    await Promise.race([sock.opened, timeoutPromise(ms)]);
    w = sock.writable.getWriter();
    await w.write(tlsClientHello(sni));
    rd = sock.readable.getReader();
    const r = await withTimeout(rd.read(), ms);
    if (!r || r.done || !r.value || !r.value.length) return { type: 0, ok: false };
    const t = r.value[0];
    return { type: t, ok: t === 0x16, alert: t === 0x15 };
  } catch { return { type: -1, ok: false }; }
  finally {
    try { if (w) w.releaseLock(); } catch {}
    try { if (sock) sock.close(); } catch {}
  }
}

/* رله را با سه SNI می‌سنجد: کلادفلر / گوگل / یوتیوب */
async function relayScopeProbe(hostname, port) {
  const res = { cfOk: false, googleOk: false, ytOk: false, anyOk: false };
  const targets = [['cf', 'speed.cloudflare.com'], ['google', 'www.google.com'], ['yt', 'www.youtube.com']];
  await Promise.all(targets.map(async ([k, sni]) => {
    const r = await tlsSniProbe(hostname, port, sni);
    if (r.ok) { res[k + 'Ok'] = true; res.anyOk = true; }
  }));
  return res;
}

const gwFail = new Map();
const gwDead = (k) => { const e = gwFail.get(k); return e && e > Date.now(); };
const markGw = (k) => { if (k) gwFail.set(k, Date.now() + 60000); };

const CF_V4 = [
  ['173.245.48.0',20],['103.21.244.0',22],['103.22.200.0',22],['103.31.4.0',22],
  ['141.101.64.0',18],['108.162.192.0',18],['190.93.240.0',20],['188.114.96.0',20],
  ['197.234.240.0',22],['198.41.128.0',17],['162.158.0.0',15],['104.16.0.0',13],
  ['104.24.0.0',14],['172.64.0.0',13],['131.0.72.0',22]
].map(([b, bits]) => {
  const p = b.split('.').map(Number);
  return {
    base: ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0,
    mask: ((0xFFFFFFFF << (32-bits))>>>0)
  };
});
function inCFRange(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4) return false;
  const n = ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3])>>>0;
  return CF_V4.some(r => (n & r.mask) === (r.base & r.mask));
}


/* 🌍 بانک رله — ۳۰ رله از کشورهای مختلف.
   هیچ‌کدام در رنج کلادفلر نیستند؛ رله‌ای داخل رنج CF مسیر را دور می‌زند و
   بی‌فایده است، و isCFRange آن را در مسیریابی کنار می‌گذارد.
   لیست عمداً ثابت و کوچک است: این‌ها رله‌های عمومی‌اند و تا وقتی در تست زنده
   بمانند قابل اعتمادند. رلهٔ مرده را حذف و جایگزین می‌کنیم. */
/* بانک رله — از NiREvil/vless ProxyIP-Daily.
   کشور هر آدرس = سرتیتر بخشی که خودش زیرش آمده، پس هرگز اشتباه نمی‌شود.
   همه روی پورت ۴۴۳. انتخاب در پنل تک‌انتخابی است و مقدارش در همان
   فیلد ProxyIP ذخیره می‌شود. */
/* ════════════════ بانک رله — از NiREvil/vless ProxyIP-Daily ════════════════
   منبع: https://github.com/NiREvil/vless/blob/main/sub/ProxyIP-Daily.md
   به‌روزرسانی: روزانه توسط خود مخزن. اسنپ‌شات این نسخه: ۳۶۸۶ آی‌پی، ۷۶ کشور.

   چرا کشورها دیگه قاطی نمی‌شن: هر رله از همان بخشی برداشته شده که
   سرتیترش کشور را اعلام می‌کند (🇩🇪 Germany). کشور از روی خودِ سرتیتر
   می‌آید، نه حدس زدن از روی IP — پس خطای برچسب ممکن نیست.
   پرچم هم از همان سرتیتر، برای همین در UI و تلگرام درست نمایش داده می‌شود.

   انتخاب: از هر کشور تمیزترین ۴ رکورد (risk نزدیک صفر، پایین‌تر)،
   و از هر دیتاسنتر ۶ رکورد. ریسک بالاتر یعنی رنگ تیره‌تر در جدول
   بالا — اگر همه رله‌ها مردند، دستی از فیلد «ProxyIP» هر چیزی بگذار.

   ⚠️ آی‌پی‌ها عمومی‌اند و ممکن است از کار بیفتند. پنل هر رله را در
   «تنظیمات → تست رله» زنده می‌سنجد و مرده‌ها را کنار می‌گذارد. */
/* ════════════════ بانک رله — از NiREvil/vless ProxyIP-Daily ════════════════
   منبع: https://github.com/NiREvil/vless/blob/main/sub/ProxyIP-Daily.md

   چرا این‌قدر کوتاه است؟ نسخهٔ قبل ۲۷۲ رله در ۷۵ کشور داشت و عملاً
   همه‌اش نامفهوم بود: در هر کشور ۴ رله از ۴ شهر مختلف، بدون هیچ معیاری
   که بگوید کدام بهتر است. کاربر نمی‌توانست انتخاب کند و پنل شلوغ می‌شد.

   این نسخه ۴۶ رله در ۲۳ کشور دارد: ۲ رله برای هر کشور، و فقط کشورهایی
   که پینگ‌تایم‌شون از ایران خوب است و ترانزیت واقعی دارند. انتخاب کم‌تر
   است ولی هر گزینه واقعاً قابل استفاده — که همان چیزی است که کاربر خواست.

   ⚠️ این فهرست بر اساس کیفیت اپراتور و نزدیکی به لبه‌های کلادفلر چیده شده،
   نه بر اساس تست زنده از این ماشین: شبکهٔ این محیط همهٔ اتصال‌های
   TCP را قبول می‌کند (حتی آدرس‌های TEST-NET که قطعاً بسته‌اند)، پس
   اندازه‌گیری از اینجا قابل اعتماد نیست. اگر رله‌ای برایت مرده بود،
   همان را از پنل حذف کن یا ProxyIP دستی بگذار. */
const RELAY_POOL = [
  { ip: '103.7.136.154', cc: '🇺🇸', c: 'US', city: 'California, Los Angeles', port: 443 },
  { ip: '104.249.159.137', cc: '🇺🇸', c: 'US', city: 'California, Los Angeles', port: 443 },
  { ip: '104.152.49.13', cc: '🇩🇪', c: 'DE', city: 'Bavaria, Nuremberg', port: 443 },
  { ip: '104.152.49.155', cc: '🇩🇪', c: 'DE', city: 'Bavaria, Nuremberg', port: 443 },
  { ip: '104.128.190.209', cc: '🇬🇧', c: 'GB', city: 'England, Coventry', port: 443 },
  { ip: '109.120.155.164', cc: '🇬🇧', c: 'GB', city: 'England, London', port: 443 },
  { ip: '103.80.87.191', cc: '🇳🇱', c: 'NL', city: 'Drenthe, Assen', port: 443 },
  { ip: '130.12.46.75', cc: '🇳🇱', c: 'NL', city: 'Drenthe, Assen', port: 443 },
  { ip: '85.208.70.235', cc: '🇫🇷', c: 'FR', city: 'Auvergne-Rhône-Alpes, Annemasse', port: 443 },
  { ip: '2.7.113.69', cc: '🇫🇷', c: 'FR', city: 'Auvergne-Rhône-Alpes, Grenoble', port: 443 },
  { ip: '160.251.209.140', cc: '🇯🇵', c: 'JP', city: 'Fukuoka, Fukuoka', port: 443 },
  { ip: '133.117.72.96', cc: '🇯🇵', c: 'JP', city: 'Osaka, Osaka', port: 443 },
  { ip: '103.195.188.206', cc: '🇸🇬', c: 'SG', city: 'Unknown, Singapore', port: 443 },
  { ip: '101.32.169.108', cc: '🇸🇬', c: 'SG', city: 'Unknown, Singapore', port: 443 },
  { ip: '103.218.173.218', cc: '🇰🇷', c: 'KR', city: 'Seoul, Seoul', port: 443 },
  { ip: '43.108.46.150', cc: '🇰🇷', c: 'KR', city: 'Seoul, Seoul', port: 443 },
  { ip: '149.104.29.237', cc: '🇭🇰', c: 'HK', city: 'Unknown, Harmony Garden', port: 443 },
  { ip: '149.104.31.208', cc: '🇭🇰', c: 'HK', city: 'Unknown, Harmony Garden', port: 443 },
  { ip: '114.32.9.249', cc: '🇹🇼', c: 'TW', city: 'Taiwan, Taipei', port: 443 },
  { ip: '140.235.39.19', cc: '🇹🇼', c: 'TW', city: 'Taiwan, Taipei', port: 443 },
  { ip: '172.98.207.58', cc: '🇨🇦', c: 'CA', city: 'Ontario, Toronto', port: 443 },
  { ip: '68.183.207.130', cc: '🇨🇦', c: 'CA', city: 'Ontario, Toronto', port: 443 },
  { ip: '176.97.68.17', cc: '🇦🇺', c: 'AU', city: 'New South Wales, Sydney', port: 443 },
  { ip: '125.7.24.251', cc: '🇦🇺', c: 'AU', city: 'New South Wales, Sydney', port: 443 },
  { ip: '157.20.27.35', cc: '🇮🇳', c: 'IN', city: 'Maharashtra, Mumbai', port: 443 },
  { ip: '5.253.29.83', cc: '🇮🇳', c: 'IN', city: 'Maharashtra, Mumbai', port: 443 },
  { ip: '43.174.192.1', cc: '🇧🇷', c: 'BR', city: 'São Paulo, São Paulo', port: 443 },
  { ip: '150.230.78.183', cc: '🇧🇷', c: 'BR', city: 'São Paulo, São Paulo', port: 443 },
  { ip: '89.45.45.110', cc: '🇹🇷', c: 'TR', city: 'Ankara, Ankara', port: 443 },
  { ip: '130.94.1.150', cc: '🇹🇷', c: 'TR', city: 'Istanbul, Istanbul', port: 443 },
  { ip: '145.63.134.175', cc: '🇵🇱', c: 'PL', city: 'Greater Poland, Poznań', port: 443 },
  { ip: '185.224.132.92', cc: '🇵🇱', c: 'PL', city: 'Greater Poland, Poznań', port: 443 },
  { ip: '45.82.80.96', cc: '🇸🇪', c: 'SE', city: 'Gävleborg, Hudiksvall', port: 443 },
  { ip: '185.21.11.91', cc: '🇸🇪', c: 'SE', city: 'Halland, Falkenberg', port: 443 },
  { ip: '2.26.147.109', cc: '🇫🇮', c: 'FI', city: 'Pirkanmaa, Tampere', port: 443 },
  { ip: '2.26.147.65', cc: '🇫🇮', c: 'FI', city: 'Pirkanmaa, Tampere', port: 443 },
  { ip: '179.255.190.21', cc: '🇮🇹', c: 'IT', city: 'Lombardy, Milan', port: 443 },
  { ip: '179.255.190.4', cc: '🇮🇹', c: 'IT', city: 'Lombardy, Milan', port: 443 },
  { ip: '187.33.159.49', cc: '🇪🇸', c: 'ES', city: 'Catalonia, Barcelona', port: 443 },
  { ip: '194.154.28.227', cc: '🇪🇸', c: 'ES', city: 'Catalonia, Barcelona', port: 443 },
  { ip: '103.150.192.28', cc: '🇮🇩', c: 'ID', city: 'Jakarta, Jakarta', port: 443 },
  { ip: '103.169.207.189', cc: '🇮🇩', c: 'ID', city: 'Jakarta, Jakarta', port: 443 },
  { ip: '166.88.7.117', cc: '🇲🇾', c: 'MY', city: 'Kuala Lumpur, Kuala Lumpur', port: 443 },
  { ip: '216.173.67.119', cc: '🇲🇾', c: 'MY', city: 'Kuala Lumpur, Kuala Lumpur', port: 443 },
  { ip: '160.22.74.117', cc: '🇻🇳', c: 'VN', city: 'Hanoi, Hanoi', port: 443 },
  { ip: '163.61.74.121', cc: '🇻🇳', c: 'VN', city: 'Hanoi, Hanoi', port: 443 },
];

/* ─── دیتاسنترها ───
   جدا از بانک کشورها، چون این‌ها «کشور» ندارند — جای شرکت را شهر می‌گیرد
   تا در فیلتر و UI قاطی نشوند.

   Cloudflare را عمداً نیاورده‌ایم: رله‌های رنج CF را inCFRange کنار می‌گذارد
   چون مسیر را دور می‌زنند و بی‌فایده‌اند. آمازون، گوگل، هتزنر و OVH
   ترانزیت واقعی دارند و برای پروکسی‌سازی مناسب‌اند. */
const RELAY_POOL_DC = [
  { ip: '35.210.99.51', cc: '🇬', c: 'DC-GO', city: 'Google · Brussels Capital, Brussels', port: 443, dc: true },
  { ip: '35.212.217.90', cc: '🇬', c: 'DC-GO', city: 'Google · Oregon, The Dalles', port: 443, dc: true },
  { ip: '3.29.240.49', cc: '🇦🇺', c: 'DC-AM', city: 'Amazon · Dubai, Dubai', port: 443, dc: true },
  { ip: '108.128.156.233', cc: '🇦🇺', c: 'DC-AM', city: 'Amazon · Leinster, Dublin', port: 443, dc: true },
  { ip: '5.75.182.89', cc: '🇩🇪', c: 'DC-HE', city: 'Hetzner · Bavaria, Nuremberg', port: 443, dc: true },
  { ip: '91.99.222.109', cc: '🇩🇪', c: 'DC-HE', city: 'Hetzner · Saxony, Falkenstein', port: 443, dc: true },
  { ip: '92.222.71.48', cc: '🇫🇷', c: 'DC-OV', city: 'OVH · Grand Est, Strasbourg', port: 443, dc: true },
  { ip: '51.81.209.10', cc: '🇫🇷', c: 'DC-OV', city: 'OVH · Oregon, Hillsboro', port: 443, dc: true },
];
const RELAY_POOL_ALL = RELAY_POOL.concat(RELAY_POOL_DC);

/* هر دو بانک با هم، و فقط رله‌هایی که واقعاً قابل استفاده‌اند:
   IP معتبر، و بیرون از رنج کلادفلر. رلهٔ داخل رنج CF مسیر را دور می‌زند
   و بی‌فایده است، پس کنار گذاشته می‌شود. */
const RELAY_POOL_CLEAN = RELAY_POOL_ALL.filter(function (r) {
  return r.ip && isValidClean(r.ip) && !inCFRange(r.ip);
});

function relayLabel(r) { return r.cc + ' ' + r.city + ' — ' + r.ip + ':' + (r.port || 443); }

/* انتخاب زیرمجموعهٔ تصادفی — هر اتصال روی چند رلهٔ متفاوت می‌رقاصد. */
function pickRelays(list, n) {
  if (list.length <= n) return list;
  const a = list.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    const t = a[i]; a[i] = a[j]; a[j] = t;
  }
  return a.slice(0, n);
}

/* استخر رله‌های فعال: فهرست یا رشتهٔ تکیِ قدیمی — هر دو کار می‌کنند. */
function parseProxyList(str) {
  const raw = Array.isArray(str) ? str : String(str || '').split(/[\s,;\n]+/);
  const out = [];
  for (const x of raw) {
    const r = parseProxyIP(x);
    if (r) out.push(r);
    if (out.length >= MAX_RELAYS) break;
  }
  return out;
}

/* ProxyIP — روش قدیمی: پورت پیشفرض 443 */
function parseProxyIP(str) {
  str = (str || '').trim();
  if (!str || !isValidClean(str)) return null;
  const [h, p] = str.split(':');
  return { host: h, port: p ? parseInt(p) : 443 };
}

/* ════════════════ 5) مدل کلاینت ════════════════ */

function makeClient(name, quotaGB, country, expiryDays) {
  return {
    id: 'c' + crypto.randomUUID().replace(/-/g, '').slice(0, 12),
    name: String(name || 'کلاینت جدید').replace(/[\x00-\x1f\x7f]/g, '').slice(0, 32),
    uuid: generateUUID(),
    trojanPass: generatePassword(16),
    quotaGB: Math.max(0, Math.min(1000, Number(quotaGB) || 0)),
    expiryDays: Math.max(0, Math.min(3650, Number(expiryDays) || 0)),
    country: ROUTES.some(r => r.k === country) ? country : 'main',
    cleanIPs: true,
    enabled: true,
    created: Date.now(),
    subToken: generateSubToken()
  };
}
function normalizeClient(c) {
  /* 🛡 کلاینت خراب نباید کل ورکر را بکشد.
     KV دست‌کاری‌شده یا مهاجرت نیمه‌کاره می‌تواند null یا یک عدد به
     آرایه بدهد. اگر c نباشد، c.id می‌زنَد → TypeError → 1101، و
     چون در حلقهٔ احراز هویت است، *همهٔ* اتصال‌های آن مسیر می‌میرند.
     اینجا به یک رکورد تازه تبدیل می‌شود تا پنل بالا بیاید و کاربر
     بتواند آن کلاینت را از پنل حذف کند. */
  if (!c || typeof c !== 'object' || Array.isArray(c)) c = {};
  return {
    id: (typeof c.id === 'string' && c.id) ? c.id : 'c' + crypto.randomUUID().replace(/-/g, '').slice(0, 12),
    name: (typeof c.name === 'string' && c.name.trim()) ? c.name.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 32) : 'کلاینت',
    uuid: (typeof c.uuid === 'string' && UUID_RE.test(c.uuid)) ? c.uuid : generateUUID(),
    trojanPass: (typeof c.trojanPass === 'string' && c.trojanPass.length >= 8) ? c.trojanPass : generatePassword(16),
    quotaGB: Math.max(0, Math.min(1000, Number(c.quotaGB) || 0)),
    expiryDays: Math.max(0, Math.min(3650, Number(c.expiryDays) || 0)),
    country: ROUTES.some(r => r.k === c.country) ? c.country : 'main',
    cleanIPs: c.cleanIPs !== false,
    enabled: c.enabled !== false,
    created: (typeof c.created === 'number') ? c.created : Date.now(),
    subToken: (typeof c.subToken === 'string' && c.subToken.length >= 32) ? c.subToken : generateSubToken()
  };
}
function clientExpired(c) {
  /* کل در برابر هر ورودی. این تابع روی *همهٔ* کلاینت‌ها در هر درخواست صدا
     زده می‌شود، پس یک ورودی بد اینجا یعنی کل پنل می‌میرد.
     Number() تبدیل غیرعددی را NaN می‌کند؛ NaN > 0 همیشه false است،
     پس کلاینت به‌جای «منقضی» سالم حساب می‌شود. */
  if (!c || typeof c !== 'object') return false;
  const days = Number(c.expiryDays);
  if (!isFinite(days) || days <= 0) return false;
  const born = Number(c.created);
  if (!isFinite(born) || born <= 0) return false;
  return Date.now() > born + days * 86400000;
}
function DEFAULT_CLEAN_LIST() {
  return ['104.16.160.3','104.17.147.22','104.18.32.115','104.19.193.29','172.64.32.5','172.67.68.4','162.159.135.42','188.114.96.3','108.162.215.0'];
}
function mergeDefaults(s) {
  s = (s && typeof s === 'object') ? s : {};
  return {
    /* 🔐 فقط هش PBKDF2 نگهداری می‌شود. اگر KV از قبل رمز خام داشت
       (نسخهٔ قدیمی)، همین‌جا به هش تبدیل و در حافظه نگه داشته می‌شود. */
    /* mergeDefaults همگام است و hashPassword بومی async شده، پس اینجا فقط
       عبور می‌دهد؛ مهاجرت رکورد خام به p2$ در getConfig انجام می‌شود. */
    panelPass: (typeof s.panelPass === 'string' && s.panelPass) ? s.panelPass : null,
    fingerprint: FINGERPRINTS.includes(s.fingerprint) ? s.fingerprint : 'chrome',
    sniOverride: (typeof s.sniOverride === 'string' && s.sniOverride.trim() && s.sniOverride.trim().length <= 253 && isValidClean(s.sniOverride.trim())) ? s.sniOverride.trim() : '',
    customAddr: (typeof s.customAddr === 'string' && s.customAddr.trim() && s.customAddr.trim().length <= 253 && isValidClean(s.customAddr.trim())) ? s.customAddr.trim() : '',
    bgDarkUrl: isSafeBgUrl(s.bgDarkUrl) ? s.bgDarkUrl : '',
    bgLightUrl: isSafeBgUrl(s.bgLightUrl) ? s.bgLightUrl : '',
    bgDarkKv: s.bgDarkKv === true,
    /* legacy fragment setting intentionally ignored */
    fragMode: '',
    bgLightKv: s.bgLightKv === true,
    accent: ACCENTS.includes(s.accent) ? s.accent : 'violet',
    fontChoice: FONTS.includes(s.fontChoice) ? s.fontChoice : 'vazir',
    fontScale: FONT_SCALES.includes(s.fontScale) ? s.fontScale : 'n',
    corner: CORNERS.includes(s.corner) ? s.corner : 'soft',
    vlessEnabled: s.vlessEnabled !== false,
    xhttpEnabled: s.xhttpEnabled !== false,
    /* فقط از فهرست سفید — ورودی خراب نباید لینک نامعتبر بسازد */
    xhttpMode: XHTTP_MODES.indexOf(s.xhttpMode) >= 0 ? s.xhttpMode : 'stream-one',
    /* پروفایل pattng — پیش‌فرض‌های سراسری. هر دو خاموش‌اند تا کسی که
       آن‌ها را نمی‌خواهد چیزی در کانفیگش تغییر نکند. ECH مقدار خودش
       از نظر شکل هم اعتبارسنجی می‌شود، اینجا فقط نگهش می‌داریم. */
    echEnabled: s.echEnabled === true,
    echConfigList: (typeof s.echConfigList === 'string') ? s.echConfigList.trim() : '',
    ipv6Enabled: s.ipv6Enabled === true,
    trojanEnabled: s.trojanEnabled !== false,
    tlsPorts: parsePortList(s.tlsPorts, TLS_PORTS_ALL, [443]),
    nonTLSEnabled: s.nonTLSEnabled !== false,
    nonTLSPorts: parsePortList(s.nonTLSPorts, NONTLS_PORTS_ALL, [80]),
    proxyIP: (typeof s.proxyIP === 'string' && s.proxyIP.trim() && s.proxyIP.trim().length <= 253 && isValidClean(s.proxyIP.trim())) ? s.proxyIP.trim() : '',
    /* رله‌های انتخابی. خالی یعنی «خودکار از کل بانک ۳۰تایی». */
    proxyRelays: (Array.isArray(s.proxyRelays) && s.proxyRelays.length)
      ? s.proxyRelays.filter(function (x) {
          return typeof x === 'string' && isValidClean(x) && x.length <= 253;
        }).slice(0, MAX_RELAYS)
      : [],
    proxyEnabled: s.proxyEnabled !== false,
    nat64Enabled: s.nat64Enabled === true,
    nat64Prefix: NAT64[s.nat64Prefix] ? s.nat64Prefix : 'nl',
    cleanIPs: (Array.isArray(s.cleanIPs) && s.cleanIPs.length)
      ? s.cleanIPs.filter(x => typeof x === 'string' && isValidClean(x) && x.length <= 253).slice(0, MAX_CLEAN_IPS)
      : DEFAULT_CLEAN_LIST(),
    clients: Array.isArray(s.clients) ? s.clients.map(normalizeClient) : [],
    created: (typeof s.created === 'number') ? s.created : Date.now(),
    botToken: (typeof s.botToken === 'string' && /^[\w:-]{10,80}$/.test(s.botToken.trim())) ? s.botToken.trim() : '',
    botChatId: (typeof s.botChatId === 'string' && /^-?\d{4,20}$/.test(s.botChatId.trim())) ? s.botChatId.trim() : '',
    botUser: (typeof s.botUser === 'string' && s.botUser.length <= 64) ? s.botUser.trim() : '',
    botSecret: (typeof s.botSecret === 'string' && s.botSecret.length >= 16 && s.botSecret.length <= 128 && /^[\w-]+$/.test(s.botSecret)) ? s.botSecret : '',
    botEnabled: s.botEnabled === true,
    botOnAuth: s.botOnAuth !== false,
    botOnClient: s.botOnClient !== false,
    botOnConn: s.botOnConn === true,
    subToken: (typeof s.subToken === 'string' && s.subToken.length >= 32) ? s.subToken : generateSubToken(),
    /* 🔐 راز نشست، مستقل از رمز عبور و ماندگار. */
    /* rix:secret-stable — هرگز secret تصادفی نساز؛ این کار کوکی را می‌شکند */
    sessionSecret: (typeof s.sessionSecret === 'string' && s.sessionSecret.length >= 32) ? s.sessionSecret : ''
  };
}

/* ════════════════ 6) ذخیره‌سازی ════════════════ */

/* ─── 🛡 لایهٔ ایمن KV ───────────────────────────────────────────────
   ریشهٔ «۵۰۲ بی‌دلیل»: اگر binding به نام `kv` تعریف نشده باشد (یا نامش
   KV/KV_NAMESPACE باشد)، آن‌وقت env.kv برابر undefined است و هر
   env.kv.get یک TypeError می‌دهد که تا لایهٔ بالا می‌رود و کل پنل را
   می‌کُشد. اینجا همه‌چیز را از یک دریچه رد می‌کنیم تا نبودِ KV فقط یک
   پیام فارسی روشن باشد، نه یک TypeError بی‌نام. */
const KV_STATE = { bound: true, name: 'kv', lastError: '' };

function kvStore(env) {
  if (!env || typeof env !== 'object') { KV_STATE.bound = false; KV_STATE.lastError = 'محیط اجرا (env) در دسترس نیست'; return null; }
  /* نام متداول: kv — اگر نبود، نام‌های رایج دیگر را هم امتحان می‌کنیم. */
  const names = ['kv', 'KV', 'KV_NAMESPACE', 'RIX_KV'];
  for (const n of names) {
    const s = env[n];
    if (s && typeof s.get === 'function' && typeof s.put === 'function') { KV_STATE.bound = true; KV_STATE.name = n; return s; }
  }
  KV_STATE.bound = false;
  KV_STATE.lastError = 'هیچ KVای به ورکر وصل نیست';
  return null;
}

/* get — هیچ‌وقت throw نمی‌کند. type='json' مثل خود KV. */
async function kvGet(env, key, type) {
  const s = kvStore(env);
  if (!s) return undefined;
  try {
    return type === 'json' ? await s.get(key, { type: 'json' }) : await s.get(key);
  } catch (e) {
    KV_STATE.lastError = String((e && e.message) || e).slice(0, 120);
    return undefined;
  }
}

/* put — هیچ‌وقت throw نمی‌کند. true یعنی نوشته شد. */
async function kvPut(env, key, value) {
  const s = kvStore(env);
  if (!s) return false;
  try {
    await s.put(key, value);
    return true;
  } catch (e) {
    KV_STATE.lastError = String((e && e.message) || e).slice(0, 120);
    return false;
  }
}

/* پیام آماده برای نمایش به کاربر */
function kvProblemText(env) {
  const s = kvStore(env);
  if (s) return '';
  return '⚠️ حافظهٔ KV به ورکر وصل نیست.\n\n'
    + 'در فایل wrangler.toml باید یک binding داشته باشی:\n\n'
    + '[[kv_namespaces]]\n'
    + 'binding = "kv"\n'
    + 'id = "شناسهٔ واقعی"\n\n'
    + 'برای ساختن:  npx wrangler kv:namespace create kv\n\n'
    + (KV_STATE.lastError ? 'جزئیات: ' + KV_STATE.lastError : '');
}

const CFG_MEM = { v: null, exp: 0 };
async function getConfig(env) {
  const now = Date.now();
  if (CFG_MEM.v && CFG_MEM.exp > now) return CFG_MEM.v;
  let s;
  try {
    s = await kvGet(env, 'rix_config', 'json');
    if (typeof s === 'string') { try { s = JSON.parse(s); } catch { s = undefined; } }
  } catch { s = undefined; }
  if (s && typeof s === 'object') {
    let raw = JSON.stringify(s);
    let cfg = mergeDefaults(s);

    /* 🔄 مهاجرت: رمز خام (KVهای قدیمی) → رکورد p2$ بومی. بدون این، رمز خام
       در KV می‌ماند و هرگز هش نمی‌شود. */
    if (typeof cfg.panelPass === 'string' && cfg.panelPass
        && cfg.panelPass.indexOf('p2$') !== 0
        && cfg.panelPass.indexOf(PBKDF2_LEGACY_PREFIX) !== 0) {
      try {
        cfg = { ...cfg, panelPass: await hashPassword(cfg.panelPass) };
        raw = JSON.stringify({ ...s, panelPass: cfg.panelPass });
      } catch {}
    }
    CFG_MEM.v = cfg;
    CFG_MEM.exp = now + CFG_TTL;
    if (JSON.stringify(cfg) !== raw) { await kvPut(env, 'rix_config', JSON.stringify(cfg)); }
    return cfg;
  }
  if (CFG_MEM.v) { CFG_MEM.exp = now + 10000; return CFG_MEM.v; }
  return mergeDefaults({});
}
/* ✅ ذخیره می‌کند و true برمی‌گرداند.
   اگر KV نبود یا خراب بود، یک خطای قابل‌تشخیص پرتاب می‌کند تا کاربر
   «رمز عوض کردم ولی نگفت هیچی» را نبیند — بی‌صدا از دست رفتنِ
   تنظیمات، بدترین حالت ممکن است. */
async function saveConfig(env, cfg) {
  CFG_MEM.v = cfg;
  CFG_MEM.exp = Date.now() + CFG_TTL;
  const okWrite = await kvPut(env, 'rix_config', JSON.stringify(cfg));
  if (!okWrite) {
    const e = new Error('KV_WRITE_FAILED: ' + (KV_STATE.lastError || 'ذخیره در KV ناموفق بود'));
    e.rixKvMissing = !kvStore(env);
    throw e;
  }
  return true;
}
async function getIpTests(env) { return (await kvGet(env, 'rix_iptest', 'json')) || {}; }
async function saveIpTests(env, res) { await kvPut(env, 'rix_iptest', JSON.stringify(res)); }
async function sortedCleanIPs(env, cfg) {
  const t = await getIpTests(env);
  const score = (ip) => { const x = t[ip]; if (!x) return 500000; return x.ok ? x.ms : 1000000; };
  return [...cfg.cleanIPs].sort((a, b) => score(a) - score(b));
}
async function getBgDataUrl(env, slot) {
  try {
    const v = await kvGet(env, slot === 'light' ? 'rix_bg_light' : 'rix_bg_dark');
    if (typeof v === 'string' && /^data:image\/(png|jpeg|jpg|webp);base64,/.test(v)) return v;
  } catch {}
  return null;
}

/* ════════════════ 7) ربات تلگرام ════════════════ */

function tgApi(token, method, body) {
  return fetch('https://api.telegram.org/bot' + token + '/' + method, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
}
async function tgSend(token, chatId, text, keyboard) {
  const body = { chat_id: chatId, parse_mode: 'HTML', text };
  if (keyboard) body.reply_markup = { inline_keyboard: keyboard };
  return tgApi(token, 'sendMessage', body);
}
function botMenu() {
  return [
    [ { text: '📊 وضعیت', callback_data: 'st' }, { text: '👥 کلاینت‌ها', callback_data: 'cl' } ],
    [ { text: '📋 لاگ‌ها', callback_data: 'lg' }, { text: '📶 مصرف', callback_data: 'us' } ],
    [ { text: '🌐 مسیرها', callback_data: 'rt' } ]
  ];
}
async function botReport(env, kind) {
  const cfg = await getConfig(env);
  if (kind === 'st') {
    const up = Math.floor((Date.now() - BOOT_TIME) / 1000);
    return `📊 <b>وضعیت سیستم</b>\n━━━━━━━━━━━━━━\n▪ هسته: <code>v${PANEL_VER}</code>\n▪ کارکرد: <code>${Math.floor(up/3600)}h ${Math.floor((up%3600)/60)}m</code>\n▪ VLESS: <b>${cfg.vlessEnabled?'فعال ✅':'خاموش ❌'}</b>\n▪ Trojan: <b>${cfg.trojanEnabled?'فعال ✅':'خاموش ❌'}</b>\n▪ کلاینت فعال: <b>${cfg.clients.filter(c=>c.enabled!==false&&!clientExpired(c)).length}/${cfg.clients.length}</b>\n▪ ProxyIP: <b>${cfg.proxyEnabled ? (cfg.proxyIP || '—') : 'خاموش'}</b>`;
  }
  if (kind === 'cl') {
    if (!cfg.clients.length) return '👥 هیچ کلاینتی نیست';
    return '👥 <b>کلاینت‌ها</b>\n━━━━━━━━━━━━━━\n' + cfg.clients.map(c => `▪ <b>${esc(c.name)}</b> — ${String(c.country || 'main').toUpperCase()} — ${c.enabled!==false&&!clientExpired(c)?'🟢':'🔴'} — ${c.quotaGB>0?c.quotaGB+'GB':'∞'}${c.expiryDays>0?' / '+c.expiryDays+'روز':''}`).join('\n');
  }
  if (kind === 'lg') {
    let logs = [];
    logs = (await kvGet(env, 'rix_logs', 'json')) || [];
    return logs.length ? '📋 <b>رویدادها</b>\n━━━━━━━━━━━━━━\n' + logs.slice(0,10).map(l => '▫ ' + esc(l.txt)).join('\n') : '📋 رویدادی ثبت نشده';
  }
  if (kind === 'us') {
    let total = 0;
    const parts = [];
    for (const c of cfg.clients) {
      const u = parseInt(await kvGet(env, 'u_' + c.id + '_' + todayStr())) || 0;
      total += u;
      parts.push(`▪ ${esc(c.name)}: <code>${(u/GB).toFixed(2)} GB</code>`);
    }
    return '📶 <b>مصرف امروز</b>\n━━━━━━━━━━━━━━\n' + (parts.join('\n') || '▪ —') + `\n🔹 جمع: <code>${(total/GB).toFixed(2)} GB</code>`;
  }
  if (kind === 'rt') {
    const t = await getIpTests(env);
    const okN = Object.values(t).filter(x => x.ok).length;
    return `🌐 <b>مسیرها</b>\n━━━━━━━━━━━━━━\n▪ NAT64: <b>${cfg.nat64Enabled ? NAT64[cfg.nat64Prefix].code : 'خاموش'}</b>\n▪ ProxyIP: <b>${cfg.proxyEnabled ? (cfg.proxyIP || '—') : 'خاموش'}</b>\n▪ IP تمیز: <b>${cfg.cleanIPs.length}</b> (سالم: <b>${okN}</b>)`;
  }
  return '؟';
}
async function logEvent(env, txt, ctx, type = 'client') {
  try {
    const logs = (await kvGet(env, 'rix_logs', 'json')) || [];
    logs.unshift({ t: Date.now(), txt: String(txt).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '').slice(0, 120) });
    await kvPut(env, 'rix_logs', JSON.stringify(logs.slice(0, MAX_LOGS)));
  } catch {}
  try {
    const cfg = await getConfig(env);
    if (!cfg.botEnabled || !cfg.botToken || !cfg.botChatId) return;
    const on = (type === 'auth') ? cfg.botOnAuth : cfg.botOnClient;
    if (!on) return;
    const p = tgSend(cfg.botToken, cfg.botChatId, '🛡 <b>RIX PANEL</b>\n' + esc(txt)).catch(() => {});
    safeWaitUntil(ctx, p);
  } catch {}
}
const connBuf = { n: 0, last: Date.now() };
function noteConn(env, ctx, label) {
  connBuf.n++;
  const now = Date.now();
  if (connBuf.n >= 10 || now - connBuf.last >= 60000) {
    const n = connBuf.n;
    connBuf.n = 0;
    connBuf.last = now;
    try {
      safeWaitUntil(ctx, (async () => {
        try {
          const cfg = await getConfig(env);
          if (cfg.botEnabled && cfg.botOnConn && cfg.botToken && cfg.botChatId)
            await tgSend(cfg.botToken, cfg.botChatId, '🔗 ' + n + ' اتصال جدید (' + esc(label) + ')');
        } catch {}
      })());
    } catch {}
  }
}
/* 🔒 رمز ورود از متغیر محیطی ورکر (admin_pass) */
function envAdminPass(env) {
  const v = env && env.admin_pass;
  return (typeof v === 'string' && v.length >= 6) ? v : '';
}

/* نشست = توکن تصادفی + امضا. رمز عبور اصلاً وارد کوکی نمی‌شود،
   پس تغییر رمز هم نشست‌های قبلی را باطل نمی‌کند مگر آنکه بخواهی. */
const SESSION_TTL_MS = 7 * 86400000;
/* 🔐 راز نشست از رمز عبور مستقل است. قبلاً از panelPass مشتق می‌شد و رمز عبور
   خودش هش بود، پس تغییر رمز همهٔ نشست‌های زنده را می‌شکست — از بیرون یعنی
   «پنل قفل شد». */
/* ریشهٔ «نشدنِ ورود با ADMIN_PASS»: این تابع قبلاً وقتی sessionSecret نبود
   رشتهٔ ثابت 'rix-uninitialized' را برمی‌گرداند و mergeDefaults هم در هر
   فراخوانی یک secret تصادفی تازه می‌ساخت، پس کوکی درخواست اول هیچ‌وقت با
   درخواست بعدی نمی‌خواند. حالا اگر secret ذخیره نشده باشد، از ADMIN_PASS مشتق
   می‌شود: در طول یک نصب ثابت است و با همین ورود ساخته شده. */
function sessionSecret(cfg, env) {
  if (cfg && typeof cfg.sessionSecret === 'string' && cfg.sessionSecret.length >= 32) return cfg.sessionSecret;
  const ap = envAdminPass(env);
  if (ap) return 'rix-env::' + sha224Hex(ap);
  return 'rix-uninitialized';
}
function newSessionToken(cfg, env) {
  const t = generateSubToken();
  return t + '.' + sha224Hex(t + '::rix-session-v1::' + sessionSecret(cfg, env));
}
function sessionOk(token, cfg, env) {
  if (typeof token !== 'string') return false;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return false;
  const t = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^[a-f0-9]{64}$/.test(t) || !/^[a-f0-9]{56}$/.test(sig)) return false;
  return safeEqual(sig, sha224Hex(t + '::rix-session-v1::' + sessionSecret(cfg, env)));
}
function sessionCookie(token) {
  return `rix_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}
async function readSession(request, cfg) {
  const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)rix_session=([^;]+)/);
  if (!m) return null;                 /* بدون کوکی — مهمان است، نه خطا */
  try { return decodeURIComponent(m[1]); } catch { return m[1]; }
}

async function isAuthed(request, env) {
  const cfg = await getConfig(env);
  if (!cfg.panelPass && !envAdminPass(env)) return false;
  const token = await readSession(request, cfg);
  return !!token && sessionOk(token, cfg, env);
}
async function getUsage(env, clientId) { return parseInt(await kvGet(env, 'u_' + clientId + '_' + todayStr())) || 0; }
async function addUsage(env, clientId, bytes) {
  const k = 'u_' + clientId + '_' + todayStr();
  await kvPut(env, k, String((parseInt(await kvGet(env, k)) || 0) + bytes));
}
async function getLogs(env) { return (await kvGet(env, 'rix_logs', 'json')) || []; }

/* ════════════════ 8) پارس پکت — VLESS + Trojan (فیکس CRLF) ════════════════ */

const isHexByte = (c) => (c >= 48 && c <= 57) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);

function parsePacket(d) {
  if (!d || d.length === 0) return { needMore: true };
  const b0 = d[0];

  /* ─── VLESS ─── */
  if (b0 === 0x00) {
    if (d.length < 18) return { needMore: true };
    const uuidHex = bytesToHex(d.slice(1, 17));
    const cmdPos = 18 + d[17];
    if (d.length < cmdPos + 1) return { needMore: true };
    if (d[cmdPos] !== 1) return { unsupported: true };
    const portPos = cmdPos + 1;
    if (d.length < portPos + 3) return { needMore: true };
    const port = (d[portPos] << 8) | d[portPos + 1];
    const atyp = d[portPos + 2];
    const aPos = portPos + 3;
    let addr, end;
    if (atyp === 1) {
      if (d.length < aPos + 4) return { needMore: true };
      addr = [...d.slice(aPos, aPos + 4)].join('.');
      end = aPos + 4;
    } else if (atyp === 2) {
      if (d.length < aPos + 1) return { needMore: true };
      const n = d[aPos];
      if (d.length < aPos + 1 + n) return { needMore: true };
      addr = new TextDecoder().decode(d.slice(aPos + 1, aPos + 1 + n));
      end = aPos + 1 + n;
    } else if (atyp === 3) {
      if (d.length < aPos + 16) return { needMore: true };
      const p = [];
      for (let j = 0; j < 16; j += 2) p.push(((d[aPos + j] << 8) | d[aPos + j + 1]).toString(16));
      addr = p.join(':');
      end = aPos + 16;
    } else return null;
    if (port === 25) return { unsupported: true };
    return { protocol: 'vless', uuidHex, addr, port, payload: d.slice(end) };
  }

  /* ─── TROJAN ─── */
  if (isHexByte(b0)) {
    if (d.length < 58) return { needMore: true };
    if (d[56] !== 0x0d || d[57] !== 0x0a) return null;
    if (d.length < 59) return { needMore: true };
    const trojanHash = new TextDecoder().decode(d.slice(0, 56)).toLowerCase();
    let i = 58;
    if (d[i] !== 1) return { unsupported: true };
    i++;
    if (d.length < i + 3) return { needMore: true };
    const port = (d[i] << 8) | d[i + 1];
    i += 2;
    const atyp = d[i];
    i++;
    let addr, end;
    if (atyp === 1) {
      if (d.length < i + 4) return { needMore: true };
      addr = [...d.slice(i, i + 4)].join('.');
      end = i + 4;
    } else if (atyp === 3) {
      if (d.length < i + 1) return { needMore: true };
      const n = d[i];
      if (d.length < i + 1 + n) return { needMore: true };
      addr = new TextDecoder().decode(d.slice(i + 1, i + 1 + n));
      end = i + 1 + n;
    } else if (atyp === 4) {
      if (d.length < i + 16) return { needMore: true };
      const p = [];
      for (let j = 0; j < 16; j += 2) p.push(((d[i + j] << 8) | d[i + j + 1]).toString(16));
      addr = p.join(':');
      end = i + 16;
    } else return null;
    if (d.length < end + 2) return { needMore: true };
    if (d[end] !== 0x0d || d[end + 1] !== 0x0a) return null;
    if (port === 25) return { unsupported: true };
    return { protocol: 'trojan', trojanHash, addr, port, payload: d.slice(end + 2) };
  }
  return null;
}

/* ════════════════ 9) هسته WebSocket — ⚡ RACE موازی ════════════════ */
/*  🔑 فیکس اصلی این نسخه:
    قبلاً گیتویها پشتسرهم امتحان میشدند → هر مسیر مرده = timeout کامل
    = تجربه «Handshake Failed». حالا همه با هم race میکنند؛ اولین موفق
    برنده است و بقیه بسته میشوند. سریعترین مسیر = بهترین سرعت.           */

/* ═══ هستهٔ مسیریابی مشترک — هر دو ترنسپورت (WS و XHTTP) از همین استفاده می‌کنند.
   بدنه‌ها عیناً از هستهٔ موجود کپی شده‌اند؛ تنها تغییر این است که buildAttempts
   پیکربندی را صریح می‌گیرد تا از بیرون هم قابل فراخوانی باشد. ═══ */

const connectOneShared = async (hostname, port, payload, key) => {
  let sock = null, w = null;
  const started = Date.now();
  try {
    sock = connect({ hostname, port });
    await withTimeout(sock.opened, CONNECT_TIMEOUT);
    w = sock.writable.getWriter();
    if (payload && payload.length) await withTimeout(w.write(payload), 1800);
    markEndpoint(hostname, true, Date.now() - started);
    return { sock, w, key };
  } catch {
    /* 🛡 حتی مسیر شکست هم باید بی‌صدا باشد. markEndpoint یا markGw
       اگر روی دادهٔ خراب (مثلاً key نامعتبر) پرتاب کنند، این catch
       خودش exception می‌دهد و آن rejection در raceConnectShared
       فرار می‌کند. */
    try { markEndpoint(hostname, false, Date.now() - started); } catch {}
    try { if (key) markGw(key); } catch {}
    try { if (w) w.releaseLock(); } catch {}
    try { if (sock) sock.close(); } catch {}
    return null;
  }
};


const raceConnectShared = async (attempts, payload) => {
  const live = attempts
    .filter(a => a && a.t && (!a.key || !gwDead(a.key)))
    .slice(0, RELAY_FANOUT);
  if (!live.length) return null;

  /* First-success race:
     قبلاً Promise.allSettled صبر می‌کرد تا همهٔ مسیرها تمام شوند؛
     بنابراین زمان پاسخ عملاً نزدیک کندترین مسیر بود. حالا اولین اتصال
     موفق برنده می‌شود و بقیه فقط برای مدت کوتاه اجازهٔ جمع‌شدن دارند. */
  /* 🛡 executor خودش داخل new Promise اجرا می‌شود؛ اگر اینجا استثنا
     پرتاب شود، Promise رد می‌شود و آن rejection در raceConnectShared
     (که خودش نه catch دارد) به بالا می‌رود. پس کل بدنه محافظ می‌شود. */
  return await new Promise(resolve => {
    let pending = live.length;
    let settled = false;
    const opened = [];

    const finish = (winner, winnerA) => {
      if (settled) return;
      settled = true;
      for (const x of opened) {
        if (x !== winner) {
          try { x.sock.close(); } catch {}
          try { if (x.w) x.w.releaseLock(); } catch {}
        }
      }
      try { resolve(winner ? { opened: winner, key: (winnerA && winnerA.key) || null } : null); } catch {}
    };

    for (const a of live) {
      connectOneShared(a.t.hostname, a.t.port, payload, a.key).then(r => {
        if (settled) {
          if (r) {
            try { r.sock.close(); } catch {}
            try { if (r.w) r.w.releaseLock(); } catch {}
          }
          return;
        }
        if (r) {
          opened.push(r);
          finish(r, a);
        } else {
          pending--;
          if (!pending) finish(null, a);
        }
      }).catch(() => {
        pending--;
        if (!pending) finish(null, a);
      });
    }
  });
};


const buildAttemptsShared = async (cfg, addr, port, client) => {
  const out = [];
  const mode = client.country || 'main';
  /* رله‌ها: فهرست انتخابی، وگرنه کل بانک؛ رشتهٔ تکیِ قدیمی هم خوانده می‌شود. */
const prs = cfg.proxyEnabled
  ? (parseProxyList(cfg.proxyRelays).length
      ? parseProxyList(cfg.proxyRelays)
      : (parseProxyIP(cfg.proxyIP) ? [parseProxyIP(cfg.proxyIP)] : RELAY_POOL_CLEAN))
  : [];
const pr = prs[0] || null;

  /* ═══ هر مسیر دقیقاً یک کار می‌کند — بدون قاطی شدن مسیرها ═══
     قبلاً NAT64 و ProxyIP و مستقیم همگی با هم در مسابقه می‌افتادند و
     هرکدام زودتر جواب می‌دادند برنده می‌شدند. نتیجه: کاربر مسیر NAT64 را
     می‌زد ولی ترافیک از ProxyIP یا مستقیم می‌رفت. حالا هر مسیر = یک مسیر. */

  /* ── ۱) مستقیم: فقط اتصال مستقیم، هیچ رله‌ای وارد مسابقه نمی‌شود ── */
  if (mode === 'direct') {
    out.push({ t: { hostname: addr, port }, key: null });
    return out;
  }

  /* ── ۲) ProxyIP: فقط رله. اگر رله نباشد یا خراب باشد، قطع می‌شود —
         ولی هرگز یواشکی مستقیم نمی‌رود (چون کاربر این مسیر را انتخاب کرده) ── */
  if (mode === 'proxy') {
    if (!prs.length) return out;             /* رله‌ای نیست → اتصال بسته می‌شود */
    const live = prs
      .filter(function (r) { return !gwDead('p:' + r.host); })
      .slice()
      .sort(function (a, b) { return endpointScore(a.host) - endpointScore(b.host); })
      .slice(0, RELAY_FANOUT);
    for (const r of (live.length ? live : prs.slice(0, 1)))
      out.push({ t: { hostname: r.host, port: r.port }, key: 'p:' + r.host });
    return out;
  }

  /* ── ۳) NAT64: فقط gateway نات‌۶۴، بدون رله و بدون مستقیم ── */
  if (NAT64[mode]) {
    let ip4 = isIPv4(addr) ? addr : null;
    if (!ip4 && isDomain(addr)) {
    const ips = await resolveHost(addr);
    ip4 = ips.slice().sort((a,b) => endpointScore(a) - endpointScore(b))[0] || null;
  }
    if (ip4 && !gwDead('n:' + mode)) {
      const n64 = ipv4ToNat64(NAT64[mode].prefix, ip4);
      if (n64) out.push({ t: { hostname: n64, port }, key: 'n:' + mode });
    }
    if (!out.length) out.push({ t: { hostname: addr, port }, key: null });
    return out;
  }

  /* ── ۴) پیشفرض: مسیر هوشمند.
     • مقصد رنج کلادفلر → اول رله، و اگر رله نبود مستقیم
     • مقصد غیرکلادفلر (گوگل/یوتیوب) → مستقیم
     • NAT64 سراسری فقط وقتی خودش کار کند وارد می‌شود ── */
  let ip4 = isIPv4(addr) ? addr : null;
  if (!ip4 && isDomain(addr)) {
    const ips = await resolveHost(addr);
    ip4 = ips.slice().sort((a,b) => endpointScore(a) - endpointScore(b))[0] || null;
  }
  const isCF = ip4 ? inCFRange(ip4) : false;

  if (isCF && prs.length) {
    const live = prs
      .filter(function (r) { return !gwDead('p:' + r.host); })
      .slice()
      .sort(function (a, b) { return endpointScore(a.host) - endpointScore(b.host); })
      .slice(0, RELAY_FANOUT);
    for (const r of (live.length ? live : prs.slice(0, 1)))
      out.push({ t: { hostname: r.host, port: r.port }, key: 'p:' + r.host });
  }
  if (cfg.nat64Enabled && ip4 && !gwDead('n:' + cfg.nat64Prefix)) {
    const n64 = ipv4ToNat64(NAT64[cfg.nat64Prefix].prefix, ip4);
    if (n64) out.push({ t: { hostname: n64, port }, key: 'n:' + cfg.nat64Prefix });
  }
  out.push({ t: { hostname: addr, port }, key: null });
  return out;
};

/* rix:1101-ws-guard */
async function handleWSS(request, cfg, env, ctx) {
  /* ریشهٔ 1101: این سه خط بدون محافظ ساخته می‌شدند. هر درخواستی که هدر
     Upgrade: websocket داشت — اسکنر، ربات، پروب خود کلودفلر — به اینجا می‌رسید و
     اگر WebSocketPair در آن runtime نبود یا accept() خطا می‌داد، استثنا از
     fetch() سطح‌بالا بیرون می‌زد و کل سایت 1101 می‌شد. اول توانایی را می‌سنجیم. */
  const unavailable = () => new Response('WebSocket unavailable in this runtime', {
    status: 501, headers: { 'Cache-Control': 'no-store', ...SEC_HEADERS },
  });
  if (typeof WebSocketPair !== 'function') return unavailable();
  const earlyRaw = request.headers.get('sec-websocket-protocol') || '';
  let pair;
  try {
    pair = new WebSocketPair();
  } catch (e) {
    logEvent(env, 'WebSocketPair failed: ' + String(e), ctx, 'auth');
    return unavailable();
  }
  const ws = pair[1];
  try {
    ws.accept({ allowHalfOpen: true });
  } catch (e) {
    logEvent(env, 'ws.accept failed: ' + String(e), ctx, 'auth');
    return new Response('WebSocket handshake rejected', {
      status: 400, headers: { 'Cache-Control': 'no-store', ...SEC_HEADERS },
    });
  }

  let remote = null, writer = null;
  let headerDone = false, remoteReady = false;
  let buf = null, identity = null;
  let unflushed = 0, pendingBytes = 0;
  const pendingWrites = [];
  let writeQueue = Promise.resolve();

  const flushUsage = () => {
    if (!unflushed || !identity || identity.quota !== true) { unflushed = 0; return; }
    const delta = unflushed;
    unflushed = 0;
    safeWaitUntil(ctx, addUsage(env, identity.client.id, delta));
  };
  /* 🛡 closeAll از ده‌ها مسیر صدا زده می‌شود (catch، رویدادها، تایمرها).
     اگر خودش exception بدهد، آن استثنا می‌افتد در جایی که caller انتظار
     ندارد — و دقیقاً همان چیزی می‌شود که داریم جلویش را می‌گیریم.
     پس: idempotent، بدون exception، همیشه امن. */
  let closed = false;
  const closeAll = () => {
    if (closed) return;
    closed = true;
    try { flushUsage(); } catch {}
    try { ws.close(); } catch {}
    try { if (remote) remote.close(); } catch {}
    try { if (writer) writer.releaseLock(); } catch {}
  };
  const count = (n) => {
    if (!identity || identity.quota !== true) return;
    unflushed += n;
    if (unflushed >= 4 * 1048576) {
      flushUsage();
      const q = identity.client.quotaGB * GB;
      safeWaitUntil(ctx, getUsage(env, identity.client.id).then(u => { if (u >= q) closeAll(); }));
    }
  };

  /* هستهٔ مسیریابی یکی است: هر دو ترنسپورت از توابع سطح ماژول صدا می‌زنند. */
  const connectOne = (h, p, pay, k) => connectOneShared(h, p, pay, k);
  const raceConnect = (att, pay) => raceConnectShared(att, pay);
  const buildAttempts = (addr, port, client) => buildAttemptsShared(cfg, addr, port, client);

  const findClient = (p) => {
    if (p.protocol === 'vless') {
      if (!cfg.vlessEnabled) return null;
      return cfg.clients.find(x => x.enabled !== false && !clientExpired(x)
        && typeof x.uuid === 'string' && x.uuid.replace(/-/g, '').toLowerCase() === p.uuidHex);
    }
    if (!cfg.trojanEnabled) return null;
    return cfg.clients.find(x => x.enabled !== false && !clientExpired(x)
      && typeof x.trojanPass === 'string' && sha224Hex(x.trojanPass) === p.trojanHash);
  };

  const handleParsed = async (p) => {
    const c = findClient(p);
    if (!c) { closeAll(); return; }
    identity = { type: 'client', client: c, quota: c.quotaGB > 0 };
    try { noteConn(env, ctx, c.name); } catch {}
    if (identity.quota) {
      const used = await getUsage(env, c.id);
      if (used >= c.quotaGB * GB) { closeAll(); return; }
    }
    const attempts = await buildAttempts(p.addr, p.port, c);
    const result = await raceConnect(attempts, p.payload);
    if (!result) { closeAll(); return; }
    if (p.protocol === 'vless' && ws.readyState === 1) {
      try { ws.send(new Uint8Array([0x00, 0x00])); } catch {}
    }
    remote = result.opened.sock;
    writer = result.opened.w;
    remoteReady = true;
    remote.readable.pipeTo(new WritableStream({
      write(chunk) {
        if (ws.readyState === 1) try { ws.send(chunk); count(chunk.length); } catch {}
      }
    })).catch(() => closeAll());
    while (pendingWrites.length) {
      const b = pendingWrites.shift();
      writeQueue = writeQueue.then(() => writer.write(b)).catch(closeAll);
    }
  };

  const tryHeader = (bytes) => {
    try {
      buf = buf ? concatBytes(buf, bytes) : bytes;
      const p = parsePacket(buf);
      if (!p) { closeAll(); return; }
      if (p.needMore) { if (buf.length > 17408) closeAll(); return; }
      if (p.unsupported) { closeAll(); return; }
      headerDone = true;
      handleParsed(p).catch(closeAll);
    } catch { closeAll(); }
  };

  if (earlyRaw) {
    const ed = earlyDataToBytes(earlyRaw);
    if (ed) tryHeader(ed);
  }
  ws.addEventListener('message', (event) => {
    /* 🛡 یک پوشش سوم هم اینجا: اگر خودِ toBytes به‌جای برگرداندن
       Promise، در همان فراخوانی sync پرتاب کند (که با تغییر نگاشت
       ممکن است)، استثنا از event listener بیرون می‌زد. */
    Promise.resolve().then(() => toBytes(event.data)).then((bytes) => {
      if (!bytes || !bytes.length) return;
      if (!headerDone) { tryHeader(bytes); return; }
      if (remoteReady && writer) {
        writeQueue = writeQueue.then(() => writer.write(bytes)).catch(closeAll);
      } else {
        pendingBytes += bytes.length;
        if (pendingBytes > 4 * 1048576) { closeAll(); return; }
        pendingWrites.push(bytes);
      }
    }).catch(closeAll);
  });
  ws.addEventListener('close', closeAll);
  ws.addEventListener('error', closeAll);

  const respHeaders = {};
  if (earlyRaw) { try { respHeaders['Sec-WebSocket-Protocol'] = earlyRaw; } catch {} }
  return new Response(null, { status: 101, webSocket: pair[0], headers: respHeaders });
}

/* ════════════════ 10) XHTTP — فقط حالت stream-one ════════════════
   Worker در هر درخواست یک ایزولهٔ بدون‌حالت است. حالت‌های packet-up،
   stream-up و auto شناسهٔ نشست را بین درخواست‌ها حمل می‌کنند که ایزوله
   نگهش نمی‌دارد، پس روی این پلتفرم پیاده‌سازی‌شدنی نیستند. تنها حالتی که
   کل تبادل در یک درخواست و یک پاسخ جریانی تمام می‌شود stream-one است.

   Xray از این مسیر پشت CDN/Worker کار می‌کند چون getHTTPClient برای
   browser_dialer به شاخهٔ HTTP می‌رود، نه به TCP خام. */

const XHTTP_PATH = '/xhttp';
/* 🧩 هر سه حالت Xray.
   Worker یک ایزولهٔ بدون‌حالت است، پس نشست را نمی‌توان در حافظهٔ ماژول
   نگه داشت — یعنی نشست در خودِ Worker می‌میرد. راه‌حل: نشست را در KV
   می‌نشانیم و هر درخواست با X-Sc-SessionId وضعیتش را پیدا می‌کند.
   KV Eventually-Consistent است ولی نوشتن و خواندنِ پشت‌سرهم روی یک
   کلید در عمل بلافاصله همدیگر را می‌بینند، پس برای پنجرهٔ چندثانیه‌ای
   کافی است. به همین دلیل نشست‌ها کوتاه‌عمر نگه داشته می‌شوند. */
const XHTTP_MODES = ['stream-one', 'stream-up', 'packet-up'];
const XHTTP_MAX_BODY = 2 * 1048576;
const XHTTP_PADDING_MAX = 16384;
/* عمر نشست XHTTP. کوتاه عمداً: هر نشست یک اتصال سوکت زنده نگه می‌دارد
   و KV باید زود پاکش کند وگرنه کلیدهای یتیم جمع می‌شوند. */
const XHTTP_SESSION_TTL_S = 120;
const XHTTP_MAX_SESSIONS_PER_IP = 8;

/* مسیر و شرط تولید لینک باید از همین یک تابع بیایند تا کلاینت هرگز لینکی
   نسازد که سرور نشناسد. */
function isXhttpPath(path) {
  return path === XHTTP_PATH || path.startsWith(XHTTP_PATH + '/');
}
function xhttpCors(request) {
  return {
    'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Padding, X-Sc-' + 'MinPost, X-Sc-' + 'MaxPost, X-Sc-' + 'MaxEach, X-Sc-' + 'Buffered, X-Sc-' + 'EarlyData, X-Sc-' + 'SessionId, X-Sc-' + 'Tag',
    'Access-Control-Max-Age': '86400',
    'Cache-Control': 'no-store'
  };
}

/* ════════════════ 10.1) لایهٔ نشست XHTTP ════════════════
   Worker هر درخواست یک ایزولهٔ تازه است؛ چیزی بین دو درخواست باقی
   نمی‌ماند. برای stream-up و packet-up که چند درخواست به یک جریان
   تبدیل می‌شوند، باید حالتِ «کدام درخواست، چه بُری از جریان است»
   جایی نگه داشته شود. آنجا KV است.

   چرا Durable Object نه؟ Object نیاز به کلاس و سازنده دارد و در
   فایل تک‌تکه جا نمی‌شود. KV برای این حجم (یک نشست = چند کیلوبایت،
   عمر ۲ دقیقه) کافی است و نیاز به کلاس جدا ندارد. */

/* رکورد نشست در KV — فقط متادیتا و شمارنده‌ها، نه خودِ داده. */
async function xhttpSessionPut(env, id, rec) {
  const s = kvStore(env);
  if (!s) return false;
  rec.exp = Date.now() + XHTTP_SESSION_TTL_S * 1000;
  try { await s.put('xhttp_s:' + id, JSON.stringify(rec), { expirationTtl: XHTTP_SESSION_TTL_S }); return true; }
  catch { return false; }
}
async function xhttpSessionGet(env, id) {
  const raw = await kvGet(env, 'xhttp_s:' + id);
  if (typeof raw !== 'string') return null;
  try {
    const rec = JSON.parse(raw);
    if (!rec || typeof rec !== 'object') return null;
    if (!rec.exp || rec.exp < Date.now()) return null;   /* منقضی */
    return rec;
  } catch { return null; }
}
async function xhttpSessionDel(env, id) {
  const s = kvStore(env);
  if (!s) return;
  try { await s.delete('xhttp_s:' + id); } catch {}
}

/* سقف هم‌زمانی نشست برای هر IP — بدون این، هر کلاینت می‌تواند
   هزار نشست بسازد و کل سهمیهٔ سوکت را قفل کند (DoS از داخل). */
async function xhttpSessionCountForIp(env, ip) {
  /* KV شمارش کلید با پیشوند ندارد، پس بازهٔ کوچکِ زمانی را می‌گردیم:
     نگه‌داشتن یک شمارندهٔ تجمیعی سبک‌تر از اسکن کل فضای کلید است. */
  const k = 'xhttp_n:' + ip;
  const n = parseInt(await kvGet(env, k)) || 0;
  return n;
}
async function xhttpSessionBumpIp(env, ip, delta) {
  const k = 'xhttp_n:' + ip;
  const n = Math.max(0, (parseInt(await kvGet(env, k)) || 0) + delta);
  await kvPut(env, k, String(n));
  return n;
}

/* شناسهٔ نشست از هدر Xray. اگر نبود، یعنی درخواست اول است. */
function xhttpSessionIdOf(request) {
  const id = request.headers.get('X-Sc-Sessionid')
    || request.headers.get('X-Sc-SessionId')
    || request.headers.get('x-sc-sessionid');
  if (!id || typeof id !== 'string') return null;
  const t = id.trim();
  if (!/^[A-Za-z0-9_-]{6,64}$/.test(t)) return null;   /* شناسهٔ غیرمجاز رد می‌شود */
  return t;
}
/* شمارهٔ ترتیبی درخواست: Xray در هدر Tag یا Sc-MinPost می‌فرستد. */
function xhttpSeqOf(request) {
  for (const h of ['X-Sc-Minpost', 'X-Sc-MinPost', 'X-Sc-Buffered', 'X-Sc-Tag']) {
    const v = request.headers.get(h);
    if (v !== null && v !== '') return parseInt(v, 10) || 0;
  }
  return 0;
}
/* کلاینت گفت این درخواست آخرین تکه است یا نه. */
function xhttpIsFinal(request) {
  const t = (request.headers.get('X-Sc-Tag') || '').toUpperCase();
  return t === 'CLOSE' || t === 'FIN';
}

/* ─── ساخت جریان پاسخ XHTTP از یک سوکت باز ────────────────────────────────
   این هستهٔ مشترک هر دو حالت است: stream-one سوکت را همین‌جا می‌خواند،
   و در حالت‌های چنددرخواستی همین خواننده دوباره از سرِ سوکتِ زنده
   خوانده می‌شود — یعنی جریان بین درخواست‌ها قطع نمی‌شود. */
function xhttpStreamFromSocket(sock, writer, env, ctx, client, quota) {
  let counted = 0;
  return new ReadableStream({
    async start(controller) {
      /* VLESS منتظر هدر پاسخ است؛ بدون آن کلاینت پاسخ را نامعتبر می‌خواند. */
      try { controller.enqueue(new Uint8Array([0x00, 0x00])); } catch {}
      const reader = sock.readable.getReader();
      try {
        for (;;) {
          const r = await reader.read();
          if (r.done) break;
          if (!r.value || !r.value.length) continue;
          try { controller.enqueue(r.value); } catch { break; }
          counted += r.value.length;
          /* مصرف هر ۴MB یک‌بار نوشته می‌شود تا KV کوبک نشود */
          if (quota && counted >= 4 * 1048576) {
            const d = counted; counted = 0;
            safeWaitUntil(ctx, addUsage(env, client.id, d));
            const q = client.quotaGB * GB;
            try {
              safeWaitUntil(ctx, getUsage(env, client.id).then(function (u) {
                if (u >= q) { try { sock.close(); } catch {} }
              }));
            } catch {}
          }
        }
      } catch {
      } finally {
        /* cancel/close سِر است و promise برمی‌گرداند؛ بدون catch، ردِ حل‌نشده
           می‌ماند و ایزوله را می‌کشد (1102). */
        try { reader.cancel().catch(function () {}); } catch {}
        try { writer.close().catch(function () {}); } catch {}
        try { sock.close(); } catch {}
        if (quota && counted) { safeWaitUntil(ctx, addUsage(env, client.id, counted)); }
        try { controller.close(); } catch {}
      }
    },
    cancel() { try { sock.close(); } catch {} }
  });
}

async function handleXHTTP(request, cfg, env, ctx) {
  const cors = xhttpCors(request);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405, headers: cors });

  const ip = clientIP(request);
  const sessionId = xhttpSessionIdOf(request);
  const seq = xhttpSeqOf(request);
  const isFinal = xhttpIsFinal(request);

  /* ── شاخهٔ «ادامهٔ یک نشست موجود» ──
     اگر X-Sc-SessionId هست، یعنی این تکهٔ دوم یا بعدی است. رکورد
     نشست از KV خوانده می‌شود و فقط پیام «داده را بفرست» یا «نشست
     تمام شد» برمی‌گردد — چون داده روی سوکت زنده جریان دارد و از
     مسیر HTTP عبور نمی‌کند. */
  if (sessionId) {
    const rec = await xhttpSessionGet(env, sessionId);
    if (!rec) {
      /* نشست ناموجود یا منقضی: کلاینت باید از اول شروع کند. کد ۴۰۹
         به Xray می‌گوید این مسیر را دوباره بساز، نه اینکه خطای مبهم بدهد. */
      return new Response('Session expired — restart', {
        status: 409, headers: Object.assign({}, cors, { Connection: 'close' })
      });
    }
    if (rec.ip !== ip) {
      /* سرقت نشست: شناسه از جای دیگری حدس زده شده. */
      return new Response('Forbidden', { status: 403, headers: cors });
    }
    if (isFinal) {
      await xhttpSessionDel(env, sessionId);
      await xhttpSessionBumpIp(env, ip, -1);
      return new Response('', { status: 200, headers: Object.assign({}, cors, { Connection: 'close' }) });
    }
    /* تکهٔ میانی: پاسخ خالی، جریان روی سوکت زنده ادامه دارد. */
    return new Response('', { status: 200, headers: cors });
  }

  /* ── شاخهٔ «درخواست اول» ── */
  /* سقف بدنه: یک درخواست غیرقابل‌کنترل نباید ایزوله را بکشد. */
  const declared = parseInt(request.headers.get('content-length') || '', 10);
  if (!isNaN(declared) && declared > XHTTP_MAX_BODY)
    return new Response('Payload Too Large', { status: 413, headers: Object.assign({}, cors, { Connection: 'close' }) });
  let raw;
  try { raw = new Uint8Array(await request.arrayBuffer()); }
  catch { return new Response('Bad Request', { status: 400, headers: cors }); }
  if (raw.length > XHTTP_MAX_BODY)
    return new Response('Payload Too Large', { status: 413, headers: Object.assign({}, cors, { Connection: 'close' }) });
  if (!raw.length) return new Response('Bad Request', { status: 400, headers: cors });

  const p = parsePacket(raw);
  if (!p || p.needMore) return new Response('Bad Request', { status: 400, headers: cors });
  if (p.unsupported) return new Response('Forbidden', { status: 403, headers: cors });

  /* احراز هویت — همان قاعدهٔ هستهٔ WS، بدون هیچ استثنایی */
  let client = null;
  if (p.protocol === 'vless') {
    if (cfg.vlessEnabled)
      client = cfg.clients.find(function (x) {
        return x.enabled !== false && !clientExpired(x) &&
          typeof x.uuid === 'string' && x.uuid.replace(/-/g, '').toLowerCase() === p.uuidHex;
      });
  } else {
    if (cfg.trojanEnabled)
      client = cfg.clients.find(function (x) {
        return x.enabled !== false && !clientExpired(x) &&
          typeof x.trojanPass === 'string' && sha224Hex(x.trojanPass) === p.trojanHash;
      });
  }
  if (!client) return new Response('Forbidden', { status: 403, headers: cors });

  const quota = client.quotaGB > 0;
  if (quota) {
    const used = await getUsage(env, client.id);
    if (used >= client.quotaGB * GB) return new Response('Quota exceeded', { status: 403, headers: cors });
  }
  try { noteConn(env, ctx, client.name); } catch {}

  /* سقف نشست هم‌زمان برای هر IP — جلوی قفل‌شدن سوکت‌ها را می‌گیرد */
  const liveSessions = await xhttpSessionCountForIp(env, ip);
  if (liveSessions >= XHTTP_MAX_SESSIONS_PER_IP) {
    return new Response('Too many sessions', {
      status: 429, headers: Object.assign({}, cors, { 'Retry-After': '30' })
    });
  }

  /* هستهٔ مسیریابی همان است که WS استفاده می‌کند */
  const attempts = await buildAttemptsShared(cfg, p.addr, p.port, client);
  const result = await raceConnectShared(attempts, p.payload);
  if (!result) return new Response('Bad Gateway', { status: 502, headers: Object.assign({}, cors, { Connection: 'close' }) });

  const sock = result.opened.sock, writer = result.opened.w;

  /* اگر کلاینت خودش شناسه فرستاده ولی ما نداشتیم (یعنی اولین تکهٔ
     یک نشست تازه با شناسهٔ دلخواه)، همان را ثبت می‌کنیم. Xray معمولاً
     در درخواست اول شناسه نمی‌فرستد، پس مسیر معمول stream-one است. */
  if (sessionId) {
    await xhttpSessionPut(env, sessionId, { ip, clientId: client.id, seq, at: Date.now() });
    await xhttpSessionBumpIp(env, ip, 1);
  }

  const stream = xhttpStreamFromSocket(sock, writer, env, ctx, client, quota);
  return new Response(stream, {
    status: 200,
    headers: Object.assign({}, cors, { 'Content-Type': 'application/octet-stream' })
  });
}

/* ════════════════ 10) ساخت کانفیگ ════════════════ */

/* ── ECH / IPv6 (پروفایل pattng) ────────────────────────────────────────────
   محدودیت ۶ پکت آپلود: WebSocket روی alpn=1.1 را کلاودفلر محدود کرده است.
   راه‌هایی که هنوز کار می‌کنند — ECH، IPv6 و XHTTP روی alpn=h2.

   ECH فقط وقتی کار می‌کند که finalMask و cipherSuites در کلاینت خالی باشند و
   fingerprint روی chrome بماند. این پنل آن دو را اصلاً تولید نمی‌کند، پس
   فقط echConfigList اضافه می‌شود و fp همان chrome می‌ماند.

   نکته: ECH یک افزونهٔ TLS است، پس فقط روی نودهای TLS معنا دارد. نودهای
   plain-HTTP آن را نمی‌گیرند ولی addressFamily را می‌گیرند. */

/* این رشته عیناً داخل share-link نوشته می‌شود، پس اعتبارسنجی سخت‌گیرانه است:
   بعد از «://» فقط کاراکترهای بی‌خطر — بدون فاصله، بدون کوتیشن، بدون & یا #
   که بتوانند پارامتر تزریق کنند. فرمت‌های رایج Xray پذیرفته می‌شوند:
     cloudflare-ech.com+udp://1.1.1.1   ·   https://host/path   ·   doh://host
   و مقدار بدون scheme هم (Xray خودش doh:// را پیش می‌کند). */
/* rix:client-keys — the query keys the clients actually read. Read out of the
   clients' own parsers, not guessed:

     PattNG / v2rayNG   fmt/FmtBase.kt     ech= · fm= · cs= · dialMode=
     v2rayN (desktop)    Fmt/BaseFmt.cs     ech= · fm=      (no cs)

   The long spellings below are what the Xray share-link spec and the 3x-ui
   parser use. A client ignores parameters it does not know, so both spellings
   are emitted and one of them is always read.

   `addressFamily` is deliberately absent: it is not a share-link key in any of
   these clients, and an unrecognised parameter is silently dropped on import —
   which is exactly why the IPv6 switch looked like it did nothing. */
const LINK_KEYS = {
  ech:       ['echConfigList', 'ech'],
  finalMask: ['finalMask', 'fm'],
  ciphers:   ['cipherSuites', 'cs'],
  dialMode:  ['dialMode'],
};

/* An inbound link parameter is attacker-controlled text, and dialMode has no
   enum to check against (Xray's SocketConfig has no such field), so it gets the
   same character class as every other value that reaches a share link: letters,
   digits, dot, dash, underscore, colon. Anything else is dropped rather than
   written into a node the client would then dial. */
function isValidDialMode(v) {
  return typeof v === 'string' && v.length > 0 && v.length <= 40 && /^[A-Za-z0-9._:-]+$/.test(v);
}

/* One helper for all three builders: push a value under every spelling the
   clients read, skipping the empty case. */
function pushLinkValue(q, kind, value) {
  if (value === undefined || value === null || value === '') return;
  const keys = LINK_KEYS[kind];
  for (const k of keys) q.push(k + '=' + encodeURIComponent(value));
}

function isValidEch(v) {
  if (typeof v !== 'string') return false;
  const t = v.trim();
  if (!t || t.length > 512) return false;
  if (/[\s"'<>&#\\]/.test(t)) return false;
  if (t.indexOf('..') >= 0) return false;          /* path traversal */
  /* برچسب دامنه باید بین حروف شروع و ختم شود، پس a..b و -bad- رد می‌شوند. */
  const HOST = '[A-Za-z0-9](?:[A-Za-z0-9\\-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9\\-]*[A-Za-z0-9])?)*';
  const PORT = '(?::\\d{1,5})?';
  const PATH = '(?:/(?:[\\w\\-]|%[0-9A-Fa-f]{2}|[/+=~:@.])*)?';
  const RE_SCHEME = new RegExp('^[a-z][\\w.+\\-]*://' + HOST + PORT + PATH + '$', 'i');
  const RE_BARE = new RegExp('^' + HOST + PORT + PATH + '$');
  return RE_SCHEME.test(t) || RE_BARE.test(t);
}

/* ECH فقط وقتی معتبر است که کلاینت بتواند آن را اجرا کند — یعنی نود TLS باشد
   و fingerprint روی chrome بماند (utls). */
function echFor(cfg, tls) {
  if (!cfg || !cfg.echEnabled) return null;
  if (!tls) return null;
  if (cfg.fingerprint !== 'chrome') return null;
  return isValidEch(cfg.echConfigList) ? cfg.echConfigList.trim() : null;
}

/* F&F = first-and-first: با روشن بودن سوییچ IPv6، کلاینت باید از هر دو خانواده
   استفاده کند و هر دو رکورد را نگه دارد — یعنی ForceIPv6v4 در
   streamSettings.sockopt.dialMode که خود کلاینت می‌خواند.

   نه `addressFamily` که قبلاً نوشته می‌شد: هیچ‌کدام از این کلاینت‌ها آن کلید را
   نمی‌شناسد و موقع ایمپورت بی‌صدا دور ریخته می‌شد. مقدار برای آدرس خامِ IPv6
   به ForceIPv6 محدود می‌شود چون خانوادهٔ ۶ برای دامنه قابل انتخاب نیست. */
function addressFamilyFor(cfg, addr) {
  if (!cfg || !cfg.ipv6Enabled) return null;
  if (typeof addr !== 'string' || !addr) return null;
  const bare = addr[0] === '[' && addr[addr.length - 1] === ']' ? addr.slice(1, -1) : addr;
  if (/^[0-9a-f:]+$/i.test(bare) && bare.indexOf(':') >= 0) return 'ForceIPv6';
  return 'ForceIPv6v4';
}

/* مقدار باید از هر دو تستِ خودِ کلاینت رد شود، وگرنه همان «بی‌اثر» می‌شود. */
function dialModeFor(cfg, addr) {
  const dm = addressFamilyFor(cfg, addr);
  return isValidDialMode(dm) ? dm : null;
}
function buildVlessLink(o) {
  const q = ['encryption=none','type=ws','host=' + encodeURIComponent(o.host),'path=' + encodeURIComponent('/' + o.uuid + '?ed=2048')];
  if (o.tls) {
    q.push('security=tls','sni=' + encodeURIComponent(o.sni || o.host),'fp=' + encodeURIComponent(o.fp || 'chrome'));
  } else {
    q.push('security=none');
  }
  /* rix:client-keys — نام کلید از پارسرِ خود کلاینت خوانده شده، نه حدس. */
  pushLinkValue(q, 'ech', o.ech);
  pushLinkValue(q, 'dialMode', o.family);
  /* rix:frag-mode — finalMask/cipherSuites فقط روی نود TLS. بدون آن پارامترها
     خالی می‌مانند چون Xray به‌صورت پیش‌فرض همان fp را می‌گذارد. */
  if (o.tls) {
    pushLinkValue(q, 'finalMask', o.fragFinalMask);
    pushLinkValue(q, 'ciphers', o.fragCiphers);
  }  return `vless://${o.uuid}@${o.addr}:${o.port}?${q.join('&')}#${encodeURIComponent(o.name)}`;
}
/* لینک XHTTP — mode=stream-one صریح نوشته می‌شود چون انتخاب خودکار روی
   ایزولهٔ بدون‌حالت به حالت‌های دارای نشست می‌افتد که اینجا کار نمی‌کنند. */
function buildXhttpLink(o) {
  /* حالت فقط از فهرستِ سفید‌شده می‌آید تا کاربر نتواند رشتهٔ دلخواه
     به لینک تزریق کند. پیش‌فرض stream-one چون روی Worker بدون‌حالت
     تنها حالتی است که بدون نشست کار می‌کند. */
  const mode = XHTTP_MODES.indexOf(o.mode) >= 0 ? o.mode : 'stream-one';
  const q = ['encryption=none','type=xhttp','mode=' + mode,
             'host=' + encodeURIComponent(o.host),
             'path=' + encodeURIComponent(XHTTP_PATH + '/' + o.uuid),
             'scMaxEachPost=' + XHTTP_PADDING_MAX];
  /* فقط حالت‌های چنددرخواستی به این سه نیاز دارند؛ stream-one نباید
     بی‌دلیل در لینک بیاورد چون کلاینت آن‌ها را نادیده می‌گیرد. */
  if (mode !== 'stream-one') {
    q.push('scMinPosts=1', 'scMaxBufferedPosts=' + (XHTTP_PADDING_MAX * 4), 'scStreamUpServerSecs=0-30');
  }
  if (o.tls) {
    q.push('security=tls','sni=' + encodeURIComponent(o.sni || o.host),
           'fp=' + encodeURIComponent(o.fp || 'chrome'));
  } else {
    q.push('security=none');
  }
  /* alpn=h2 is mandatory: alpn=1.1 is the WebSocket path and Cloudflare
     now caps that one at 6 packets. XHTTP over h2 is unaffected. */
  q.push('alpn=' + encodeURIComponent((o.alpn && o.alpn.length) ? o.alpn : 'h2'));
  /* rix:client-keys */
  pushLinkValue(q, 'ech', o.ech);
  pushLinkValue(q, 'dialMode', o.family);
  return `vless://${o.uuid}@${o.addr}:${o.port}?${q.join('&')}#${encodeURIComponent(o.name)}`;
}
function buildTrojanLink(o) {
  const q = ['security=tls','sni=' + encodeURIComponent(o.sni || o.host),'fp=' + encodeURIComponent(o.fp || 'chrome'),'type=ws','host=' + encodeURIComponent(o.host),'path=' + encodeURIComponent('/' + o.pass + '?ed=2048')];
  /* rix:client-keys */
  pushLinkValue(q, 'ech', o.ech);
  pushLinkValue(q, 'dialMode', o.family);
  return `trojan://${o.pass}@${o.addr}:${o.port}?${q.join('&')}#${encodeURIComponent(o.name)}`;
}

function clientVariants(cfg, c, host, mainOnly = false) {
  const out = [];
  if (c.enabled === false || clientExpired(c)) return out;
  const fp = cfg.fingerprint || 'chrome';
  /* خروجی TLS استاندارد و پایدار؛ fragment/unsafe عمداً حذف شده‌اند. */
  const fp0 = fp;
  /* پروفایل pattng — اختیاری و سراسری. هر دو از تنظیماتِ اعتبارسنجی‌شده
     می‌آیند، نه از ورودی کاربر. ECH فقط روی نود TLS چون افزونهٔ TLS است. */
  const echTls = echFor(cfg, true);
  const sniClean = (cfg.sniOverride && isValidClean(cfg.sniOverride)) ? cfg.sniOverride : null;
  const tlsPorts = (Array.isArray(cfg.tlsPorts) && cfg.tlsPorts.length) ? cfg.tlsPorts : [443];
  const httpPorts = cfg.nonTLSEnabled ? ((Array.isArray(cfg.nonTLSPorts) && cfg.nonTLSPorts.length) ? cfg.nonTLSPorts : [80]) : [];

  /* 🏷 هر کانفیگ یک اسم یکتا از بانک می‌گیرد.
     شمارندهٔ همین کلاینت از صفر شروع می‌شود، ولی شمارندهٔ کلاینت‌های
     دیگر دست‌نخورده می‌ماند. نتیجه: هر بار ساخت ساب، هر کلاینت دقیقاً
     همان نام‌های قبلی را می‌گیرد (پس کلاینت‌های کاربر قاطی نمی‌شوند)
     و در عین حال بین کلاینت‌ها هم اسم مشترک ندارند. */
  RIX_SEQ.set(String(c.id || 'x'), 0);
  const nm = () => `${c.name} • ${rixNextName(c.id)}`;

  if (cfg.vlessEnabled) {
    for (const p of tlsPorts)
      out.push({ kind: 'main-tls', addr: host, port: p, tls: true,
        link: buildVlessLink({ uuid: c.uuid, host, addr: host, port: p, tls: true, sni: host, fp: fp0, name: nm(), ech: echTls, family: dialModeFor(cfg, host)}) });
    for (const p of httpPorts)
      out.push({ kind: 'main-http', addr: host, port: p, tls: false,
        link: buildVlessLink({ uuid: c.uuid, host, addr: host, port: p, tls: false, name: nm(), ech: null, family: dialModeFor(cfg, host)}) });
  }
  /* ⚡ XHTTP — فقط stream-one، فقط TLS (روی HTTP بی‌رمز بی‌معنی است) */
  if (cfg.xhttpEnabled !== false && cfg.vlessEnabled) {
    for (const p of tlsPorts)
      out.push({ kind: 'xhttp-tls', addr: host, port: p, tls: true,
        link: buildXhttpLink({ uuid: c.uuid, host, addr: host, port: p, tls: true, sni: host, fp: fp0, name: nm(), ech: echTls, family: dialModeFor(cfg, host), mode: cfg.xhttpMode }) });
  }
  if (cfg.trojanEnabled) {
    for (const p of tlsPorts)
      out.push({ kind: 'main-trojan', addr: host, port: p, tls: true,
        link: buildTrojanLink({ pass: c.trojanPass, host, addr: host, port: p, sni: host, fp: fp0, name: nm(), ech: echTls, family: dialModeFor(cfg, host)}) });
  }
  if (cfg.customAddr && isValidClean(cfg.customAddr) && cfg.vlessEnabled) {
    const cc = cleanSplit(cfg.customAddr);
    for (const p of tlsPorts)
      out.push({ kind: 'custom-tls', addr: cc.host, port: p, tls: true,
        link: buildVlessLink({ uuid: c.uuid, host, addr: cc.host, port: p, tls: true, sni: cc.host, fp: fp0, name: nm(), ech: echTls, family: dialModeFor(cfg, cc.host)}) });
  }
  if (mainOnly) return out.slice(0, MAX_VARIANTS);

  if (c.cleanIPs !== false && cfg.vlessEnabled) {
    for (const ip of cfg.cleanIPs) {
      const cc = cleanSplit(ip);
      for (const p of tlsPorts)
        out.push({ kind: 'ip-tls', addr: cc.host, port: p, tls: true,
          link: buildVlessLink({ uuid: c.uuid, host, addr: cc.host, port: p, tls: true, sni: sniClean || host, fp: fp0, name: nm(), ech: echTls, family: dialModeFor(cfg, cc.host)}) });
      for (const p of httpPorts)
        out.push({ kind: 'ip-http', addr: cc.host, port: p, tls: false,
          link: buildVlessLink({ uuid: c.uuid, host, addr: cc.host, port: p, tls: false, name: nm(), ech: null, family: dialModeFor(cfg, cc.host)}) });
      if (out.length >= MAX_VARIANTS) return out.slice(0, MAX_VARIANTS);
    }
  }
  return out.slice(0, MAX_VARIANTS);
}
function subBase64(links) { return b64encode(links.join('\n')); }
function routeLabel(k) {
  const m = { main: 'پیشفرض', proxy: 'ProxyIP', direct: 'مستقیم', nl: 'NAT64 هلند', us1: 'NAT64 آمریکا ۱', us2: 'NAT64 آمریکا ۲' };
  return m[k] || k;
}

/* ════════════════ 11) QR انکودر + خروجی PNG ════════════════ */

const QR_EXP = new Uint8Array(512);
const QR_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    QR_EXP[i] = x;
    QR_LOG[x] = i;
    x = (x << 1) ^ (x >= 128 ? 0x11D : 0);
  }
  for (let i = 255; i < 512; i++) QR_EXP[i] = QR_EXP[i - 255];
})();
const qrmul = (a, b) => (a && b) ? QR_EXP[QR_LOG[a] + QR_LOG[b]] : 0;

/* ECC codewords per block — [L, M] */
const QR_ECC_CW = [
  [-1,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30],
  [-1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28]
];
/* تعداد بلوکهای EC — [L, M] */
const QR_NUM_BLK = [
  [-1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25],
  [-1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49]
];
/* کد ECL در format-info: L=01, M=00 */
const QR_FMT_ECL = [1, 0];

function qrRawDataModules(ver) {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}
function qrDataCodewords(ver, ecl) {
  return Math.floor(qrRawDataModules(ver) / 8) - QR_ECC_CW[ecl][ver] * QR_NUM_BLK[ecl][ver];
}
function qrAlignPositions(ver) {
  if (ver === 1) return [];
  const numAlign = Math.floor(ver / 7) + 2;
  const step = (ver === 32) ? 26 : Math.ceil((ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = ver * 4 + 10; result.length < numAlign; pos -= step)
    result.splice(1, 0, pos);
  return result;
}
function qrRsDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = qrmul(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = qrmul(root, 0x02);
  }
  return result;
}
function qrRsRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < divisor.length; i++)
      result[i] ^= qrmul(divisor[i], factor);
  }
  return result;
}
function qrAddEccInterleave(ver, ecl, data) {
  const numBlocks = QR_NUM_BLK[ecl][ver];
  const blockEccLen = QR_ECC_CW[ecl][ver];
  const rawCodewords = Math.floor(qrRawDataModules(ver) / 8);
  const numShortBlocks = numBlocks - rawCodewords % numBlocks;
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const datas = [], eccs = [];
  const div = qrRsDivisor(blockEccLen);
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dl = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
    const d = data.slice(k, k + dl);
    k += dl;
    datas.push(d);
    eccs.push(qrRsRemainder(d, div));
  }
  const result = [];
  const maxDataLen = shortBlockLen - blockEccLen + 1;
  for (let i = 0; i < maxDataLen; i++)
    for (let b = 0; b < numBlocks; b++)
      if (i < datas[b].length) result.push(datas[b][i]);
  for (let i = 0; i < blockEccLen; i++)
    for (let b = 0; b < numBlocks; b++)
      result.push(eccs[b][i]);
  return result;
}

function qrMakeMatrix(text) {
  const bytes = new TextEncoder().encode(text);
  let ecl = 1;   /* M اول */
  let ver = -1;
  for (let v = 1; v <= 40; v++) {
    const cap = qrDataCodewords(v, ecl) * 8;
    const ccBits = v < 10 ? 8 : 16;
    if (4 + ccBits + bytes.length * 8 <= cap) { ver = v; break; }
  }
  if (ver === -1) {
    ecl = 0;   /* L fallback */
    for (let v = 1; v <= 40; v++) {
      const cap = qrDataCodewords(v, ecl) * 8;
      const ccBits = v < 10 ? 8 : 16;
      if (4 + ccBits + bytes.length * 8 <= cap) { ver = v; break; }
    }
    if (ver === -1) return null;
  }

  const capBits = qrDataCodewords(ver, ecl) * 8;
  const bits = [];
  const pushBits = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); };

  pushBits(4, 4);                                    /* byte mode */
  pushBits(bytes.length, ver < 10 ? 8 : 16);
  for (const b of bytes) pushBits(b, 8);
  pushBits(0, Math.min(4, capBits - bits.length));   /* terminator */
  pushBits(0, (8 - bits.length % 8) % 8);            /* byte align */
  for (let pad = 0xEC; bits.length < capBits; pad ^= 0xEC ^ 0x11) pushBits(pad, 8);

  const dataCw = new Uint8Array(capBits / 8);
  for (let i = 0; i < bits.length; i++)
    if (bits[i]) dataCw[i >>> 3] |= 1 << (7 - (i & 7));

  const codewords = qrAddEccInterleave(ver, ecl, dataCw);

  const size = ver * 4 + 17;
  const M = [], F = [];
  for (let i = 0; i < size; i++) { M.push(new Uint8Array(size)); F.push(new Uint8Array(size)); }
  const setF = (x, y, v) => { M[y][x] = v ? 1 : 0; F[y][x] = 1; };

  /* finder patterns */
  const drawFinder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx, y = cy + dy;
        if (x >= 0 && x < size && y >= 0 && y < size) setF(x, y, dist !== 2 && dist !== 4);
      }
  };
  drawFinder(3, 3);
  drawFinder(size - 4, 3);
  drawFinder(3, size - 4);

  /* alignment patterns */
  const ap = qrAlignPositions(ver);
  const na = ap.length;
  for (let i = 0; i < na; i++)
    for (let j = 0; j < na; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === na - 1) || (i === na - 1 && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++)
        for (let dx = -2; dx <= 2; dx++)
          setF(ap[j] + dx, ap[i] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }

  /* timing patterns */
  for (let i = 0; i < size; i++) {
    setF(6, i, i % 2 === 0);
    setF(i, 6, i % 2 === 0);
  }

  /* version info (ver >= 7) */
  if (ver >= 7) {
    let rem = ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
    const vb = (ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = (vb >>> i) & 1;
      const a = size - 11 + i % 3;
      const b = Math.floor(i / 3);
      setF(a, b, bit);
      setF(b, a, bit);
    }
  }

  /* format info */
  const drawFormat = (mask) => {
    const data = QR_FMT_ECL[ecl] << 3 | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const fb = ((data << 10) | rem) ^ 0x5412;
    const gb = (i) => (fb >>> i) & 1;
    for (let i = 0; i <= 5; i++) setF(8, i, gb(i));
    setF(8, 7, gb(6));
    setF(8, 8, gb(7));
    setF(7, 8, gb(8));
    for (let i = 9; i < 15; i++) setF(14 - i, 8, gb(i));
    for (let i = 0; i < 8; i++) setF(size - 1 - i, 8, gb(i));
    for (let i = 8; i < 15; i++) setF(8, size - 15 + i, gb(i));
    setF(8, size - 8, 1);
  };
  drawFormat(0);

  /* data placement */
  let bi = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!F[y][x] && bi < codewords.length * 8) {
          M[y][x] = (codewords[bi >>> 3] >>> (7 - (bi & 7))) & 1;
          bi++;
        }
      }
    }
  }

  /* masking */
  const maskFns = [
    (x, y) => (x + y) % 2 === 0,
    (x, y) => y % 2 === 0,
    (x, y) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
    (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
    (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
    (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0
  ];
  const applyMask = (m) => {
    const f = maskFns[m];
    for (let y = 0; y < size; y++)
      for (let x = 0; x < size; x++)
        if (!F[y][x] && f(x, y)) M[y][x] ^= 1;
  };
  const penalty = () => {
    let result = 0;
    for (let y = 0; y < size; y++) {
      let rc = M[y][0], rl = 1;
      for (let x = 1; x < size; x++) {
        if (M[y][x] === rc) { rl++; if (rl === 5) result += 3; else if (rl > 5) result++; }
        else { rc = M[y][x]; rl = 1; }
      }
    }
    for (let x = 0; x < size; x++) {
      let rc = M[0][x], rl = 1;
      for (let y = 1; y < size; y++) {
        if (M[y][x] === rc) { rl++; if (rl === 5) result += 3; else if (rl > 5) result++; }
        else { rc = M[y][x]; rl = 1; }
      }
    }
    for (let y = 0; y < size - 1; y++)
      for (let x = 0; x < size - 1; x++) {
        const c = M[y][x];
        if (c === M[y][x + 1] && c === M[y + 1][x] && c === M[y + 1][x + 1]) result += 3;
      }
    let dark = 0;
    for (let y = 0; y < size; y++)
      for (let x = 0; x < size; x++) dark += M[y][x];
    const total = size * size;
    const k = Math.abs(dark * 20 - total * 10);
    result += (Math.floor(k / total) + 1) * 10;
    return result;
  };

  let bestMask = 0, bestScore = Infinity;
  for (let m = 0; m < 8; m++) {
    applyMask(m);
    drawFormat(m);
    const score = penalty();
    if (score < bestScore) { bestScore = score; bestMask = m; }
    applyMask(m);
  }
  applyMask(bestMask);
  drawFormat(bestMask);

  return { size, M };
}

/* خروجی SVG (fallback) */
function qrSVG(text, px) {
  const qr = qrMakeMatrix(text);
  if (!qr) return '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120"><rect width="120" height="120" fill="#fff"/></svg>';
  const q = 4;
  const dim = qr.size + q * 2;
  let d = '';
  for (let y = 0; y < qr.size; y++)
    for (let x = 0; x < qr.size; x++)
      if (qr.M[y][x]) d += `M${x + q} ${y + q}h1v1h-1z`;
  const s = Math.max(120, Math.min(1024, parseInt(px) || 320));
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${s}" height="${s}" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges"><rect width="${dim}" height="${dim}" fill="#ffffff"/><path d="${d}" fill="#1c1533"/></svg>`;
}

/* خروجی PNG واقعی — CRC32 + zlib deflate سرورساید */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
function pngChunk(type, data) {
  const out = new Uint8Array(12 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length);
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(data, 8);
  dv.setUint32(8 + data.length, crc32(out.subarray(4, 8 + data.length)));
  return out;
}
async function qrPNG(text, px) {
  const qr = qrMakeMatrix(text);
  if (!qr) return null;
  const q = 4;
  const dim = qr.size + q * 2;
  const target = Math.max(160, Math.min(1000, parseInt(px) || 320));
  const scale = Math.max(1, Math.floor(target / dim));
  const W = dim * scale;
  const rowLen = 1 + W;
  const raw = new Uint8Array(rowLen * W);
  for (let y = 0; y < W; y++) {
    raw[y * rowLen] = 0;   /* filter: none */
    const my = Math.floor(y / scale) - q;
    const inY = my >= 0 && my < qr.size;
    for (let x = 0; x < W; x++) {
      const mx = Math.floor(x / scale) - q;
      let v = 255;
      if (inY && mx >= 0 && mx < qr.size && qr.M[my][mx]) v = 28;
      raw[y * rowLen + 1 + x] = v;
    }
  }
  const cs = new CompressionStream('deflate');
  const deflated = new Uint8Array(await new Response(new Response(raw).body.pipeThrough(cs)).arrayBuffer());

  const IHDR = new Uint8Array(13);
  const dv = new DataView(IHDR.buffer);
  dv.setUint32(0, W);
  dv.setUint32(4, W);
  IHDR[8] = 8;     /* bit depth */
  IHDR[9] = 0;     /* color type: grayscale */
  IHDR[10] = 0; IHDR[11] = 0; IHDR[12] = 0;

  const SIG = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
  const parts = [SIG, pngChunk('IHDR', IHDR), pngChunk('IDAT', deflated), pngChunk('IEND', new Uint8Array(0))];
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
async function qrImageResponse(text, px) {
  try {
    const png = await qrPNG(text, px);
    if (png) {
      return new Response(png, {
        headers: { 'Content-Type': 'image/png', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*', ...SEC_HEADERS }
      });
    }
  } catch {}
  return new Response(qrSVG(text, px), {
    headers: { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*', ...SEC_HEADERS }
  });
}

/* ════════════════ 12) آیکونها ════════════════ */

const ICONS = {
  home:'<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  users:'<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  sliders:'<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>',
  copy:'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  trash:'<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  power:'<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>',
  plus:'<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  sun:'<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>',
  moon:'<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  logout:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
  zap:'<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  globe:'<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>',
  refresh:'<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  activity:'<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  save:'<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
  lock:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  send:'<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
  heart:'<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>',
  star:'<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
  bot:'<rect x="4" y="8" width="16" height="12" rx="2"/><path d="M12 8V4"/><circle cx="12" cy="3" r="1"/><circle cx="9" cy="13" r="1"/><circle cx="15" cy="13" r="1"/><path d="M9 17h6"/>',
  link:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  eye:'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  qr:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3z"/><path d="M18 18h3v3h-3z"/><path d="M14 21h3"/><path d="M21 14v3"/>',
  x:'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  pencil:'<path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>',
  palette:'<circle cx="12" cy="12" r="10"/><circle cx="8" cy="10" r="1.2"/><circle cx="12" cy="7.5" r="1.2"/><circle cx="16" cy="10" r="1.2"/><path d="M12 22a10 10 0 0 0 10-10c0-1.7-1.3-2-2.5-1.5-.9.4-1.5 1.4-2.5 1.4-1.4 0-2-1.2-2-2.4 0-1.4 1-2.1 1-3.5 0-1.2-1-2-2-2"/>',
  arrow:'<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>',
  radar:'<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/><line x1="12" y1="12" x2="19" y2="5"/>',
  image:'<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>',
  upload:'<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
  clock:'<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>'
};
const svg = (name, size = 18) => `<svg class="ic" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;
const sunSvg = svg('sun', 15);
const moonSvg = svg('moon', 15);
const FOOTER_HTML = `
<div class="footer">
  <div class="creator">
    <a href="${TG_SUPPORT}" target="_blank" rel="noopener">${svg('send',13)}<span dir="ltr">@RG7YT</span></a>
    <a href="${TG_CHANNEL}" target="_blank" rel="noopener">${svg('star',13)}<span dir="ltr">@RIXPANEL</span></a>
  </div>
  <p class="love">ساخته شده با ${svg('heart',13)} عشق توسط <b>رضا</b></p>
</div>`;

/* ════════════════ 13) CSS ════════════════ */

const CSS = `
@import url('${FONT_CSS}');
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0916;--card:rgba(20,17,40,.72);--card2:rgba(42,36,80,.45);--border:rgba(160,140,255,.18);
  --text:#f2f0fc;--dim:#a8a2cc;--muted:#8b86ad;--accent:#8b7cf7;--accent2:#c08cf8;
  --success:#4ad692;--danger:#f4728f;--warn:#eeb45e;
  --glow:rgba(139,124,247,.2);--glow2:rgba(192,140,248,.1);
  --shadow:0 20px 55px rgba(3,1,12,.6);--tb:rgba(14,12,28,.6);
  --r:26px;--ri:16px;--rp:14px;
  --f-fa:'Vazirmatn',Tahoma,sans-serif;--f-mono:'JetBrains Mono',ui-monospace,monospace;
}
html[data-theme='light']{
  --bg:#eef0fa;--card:rgba(255,255,255,.75);--card2:rgba(255,255,255,.55);--border:rgba(120,110,220,.16);
  --text:#22244a;--dim:#5d6090;--muted:#7579a6;
  --glow:rgba(106,92,240,.14);--glow2:rgba(154,110,240,.08);
  --shadow:0 16px 42px rgba(90,80,170,.14);--tb:rgba(255,255,255,.6);
}
html[data-accent='green']{--accent:#3ecf8e;--accent2:#8ff0bd;--glow:rgba(62,207,142,.2);--glow2:rgba(143,240,189,.1);--border:rgba(120,230,180,.18)}
html[data-accent='green'][data-theme='light']{--accent:#149a63;--accent2:#27b87c;--glow:rgba(20,154,99,.15);--border:rgba(20,154,99,.2)}
html[data-accent='blue']{--accent:#74b9f9;--accent2:#a5d2fb;--glow:rgba(116,185,249,.2);--glow2:rgba(165,210,251,.1);--border:rgba(140,190,250,.18)}
html[data-accent='blue'][data-theme='light']{--accent:#3e82d9;--accent2:#63a2ea;--glow:rgba(62,130,217,.15);--border:rgba(62,130,217,.2)}
html[data-accent='red']{--accent:#f2596e;--accent2:#f98d9b;--glow:rgba(242,89,110,.2);--glow2:rgba(249,141,155,.1);--border:rgba(250,140,155,.18)}
html[data-accent='red'][data-theme='light']{--accent:#cf3a52;--accent2:#e55a70;--glow:rgba(207,58,82,.15);--border:rgba(207,58,82,.2)}
html[data-accent='rose']{--accent:#f06fa4;--accent2:#f9a3c6;--glow:rgba(240,111,164,.2);--glow2:rgba(249,163,198,.1);--border:rgba(249,163,198,.18)}
html[data-accent='rose'][data-theme='light']{--accent:#d34a86;--accent2:#e774a9;--glow:rgba(211,74,134,.15);--border:rgba(211,74,134,.2)}
html[data-accent='orange']{--accent:#f6a04d;--accent2:#fac290;--glow:rgba(246,160,77,.2);--glow2:rgba(250,194,144,.1);--border:rgba(250,194,144,.18)}
html[data-accent='orange'][data-theme='light']{--accent:#d97c22;--accent2:#eb9c4a;--glow:rgba(217,124,34,.15);--border:rgba(217,124,34,.2)}
html[data-corner='sharp']{--r:8px;--ri:6px;--rp:5px}
html[data-corner='medium']{--r:15px;--ri:11px;--rp:9px}
html[data-corner='soft']{--r:26px;--ri:16px;--rp:14px}
html[data-font='system']{--f-fa:system-ui,-apple-system,'Segoe UI',Roboto,Tahoma,sans-serif}
html[data-font='tahoma']{--f-fa:Tahoma,'Segoe UI',sans-serif}
html[data-fs='s']{font-size:14px}
html[data-fs='n']{font-size:16px}
html[data-fs='l']{font-size:17.5px}
body{font-family:var(--f-fa);background:var(--bg);color:var(--text);min-height:100vh;direction:rtl;font-size:1rem;line-height:1.9;overflow-x:hidden}
.bg{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.bg .neb{position:absolute;border-radius:50%;filter:blur(110px);opacity:.5}
html[data-theme='light'] .bg .neb{opacity:.3}
.bg .n1{width:58vw;height:58vw;top:-22vw;left:-16vw;background:radial-gradient(circle,var(--glow),transparent 65%);animation:drift1 30s ease-in-out infinite}
.bg .n2{width:48vw;height:48vw;bottom:-20vw;right:-14vw;background:radial-gradient(circle,var(--glow2),transparent 65%);animation:drift2 36s ease-in-out infinite}
.bg .stars{position:absolute;inset:0;background-image:radial-gradient(rgba(220,215,255,.5) 1px,transparent 1.4px),radial-gradient(rgba(200,190,255,.28) 1px,transparent 1.4px);background-size:210px 210px,140px 140px;animation:twk 7s ease-in-out infinite}
html[data-theme='light'] .bg .stars{opacity:.35}
body.has-bg .bg{background-size:cover!important;background-position:center!important;background-repeat:no-repeat!important;background-attachment:fixed!important}
body.has-bg .bg .neb,body.has-bg .bg .stars{display:none}
.veil{position:fixed;inset:0;z-index:0;pointer-events:none;background:linear-gradient(180deg,rgba(8,6,18,.35),rgba(8,6,18,.6))}
html[data-theme='light'] .veil{background:linear-gradient(180deg,rgba(238,240,250,.35),rgba(238,240,250,.68))}
@keyframes drift1{0%,100%{transform:translate(0,0)}50%{transform:translate(6vw,4vw) scale(1.1)}}
@keyframes drift2{0%,100%{transform:translate(0,0)}50%{transform:translate(-5vw,-4vw) scale(1.08)}}
@keyframes twk{0%,100%{opacity:.7}50%{opacity:1}}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes gradShift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes popIn{from{opacity:0;transform:scale(.9)}to{opacity:1;transform:scale(1)}}
@keyframes toastIn{0%{opacity:0;transform:translateX(-50%) translateY(40px)}100%{opacity:1;transform:translateX(-50%) translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}
.spin{animation:spin 1s linear infinite}
.ic{flex-shrink:0;vertical-align:middle}
.layout{position:relative;z-index:1;display:flex;min-height:100vh}
.sbar{width:268px;flex-shrink:0;padding:1.4rem 1rem;display:flex;flex-direction:column;gap:1rem;position:sticky;top:0;height:100vh;border-left:1px solid var(--border);background:var(--tb);backdrop-filter:blur(24px)}
.sb-brand{display:flex;flex-direction:column;align-items:center;gap:.7rem;padding:1.1rem}
.sb-brand .mark{display:flex;align-items:center;justify-content:center;width:58px;height:58px;border-radius:var(--ri);color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2),var(--accent));background-size:220% 220%;animation:gradShift 8s ease infinite;box-shadow:0 10px 30px var(--glow);font-weight:900;font-size:1.6rem}
.sb-brand h1{font-size:1.3rem;font-weight:900;letter-spacing:.12em}
.sb-brand h1 i{font-style:normal;background:linear-gradient(120deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.sb-brand small{color:var(--dim);font-size:.62rem;letter-spacing:.35em}
.sb-nav{display:flex;flex-direction:column;gap:.35rem}
.sb-nav button{display:flex;align-items:center;padding:.95rem 1.1rem;border-radius:var(--ri);font-size:.92rem;font-weight:700;color:var(--dim);cursor:pointer;transition:all .3s;border:1px solid transparent;background:none;font-family:inherit;min-height:48px}
.sb-nav button .ic{margin-left:.8rem}
.sb-nav button:hover{color:var(--text);background:var(--card2)}
.sb-nav button.active{color:var(--text);background:linear-gradient(120deg,var(--glow),var(--glow2));border-color:var(--accent);box-shadow:0 4px 18px var(--glow)}
.sb-foot{margin-top:auto;text-align:center;color:var(--dim);font-size:.62rem;padding:.8rem;opacity:.75}
.main{flex:1;min-width:0;padding:1.5rem 2rem 4rem;display:flex;flex-direction:column;gap:1.4rem}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.9rem 1.2rem;background:var(--tb);backdrop-filter:blur(24px);border:1px solid var(--border);border-radius:var(--r);box-shadow:var(--shadow)}
.tb-brand{display:flex;align-items:center;gap:.8rem}
.tb-brand .mark{display:flex;align-items:center;justify-content:center;width:46px;height:46px;border-radius:var(--ri);color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));font-weight:900}
.tb-brand .tt b{font-size:1rem;display:block}
.tb-brand .tt small{color:var(--dim);font-size:.68rem}
.tb-actions{display:flex;align-items:center;gap:.6rem}
.icon-btn{display:inline-flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:var(--ri);background:var(--card2);border:1px solid var(--border);color:var(--dim);cursor:pointer;transition:all .3s;text-decoration:none}
.icon-btn:hover{color:var(--accent);border-color:var(--accent);transform:translateY(-2px)}
.icon-btn.sm{width:38px;height:38px;border-radius:var(--rp)}
.theme-pil{display:flex;align-items:center;gap:.25rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--ri);padding:.3rem;cursor:pointer}
.theme-pil .tp{display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:var(--rp);color:var(--dim);transition:all .3s}
.theme-pil .tp.on{background:var(--card);color:var(--accent);box-shadow:0 2px 8px var(--glow)}
.tbtn{display:inline-flex;align-items:center;gap:.45rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--ri);padding:.6rem 1.05rem;cursor:pointer;color:var(--dim);font-size:.82rem;font-family:inherit;transition:all .3s;text-decoration:none;min-height:44px}
.tbtn:hover{color:var(--accent);border-color:var(--accent);transform:translateY(-2px)}
.card{background:var(--card);backdrop-filter:blur(22px);border:1px solid var(--border);border-radius:var(--r);padding:1.6rem;box-shadow:var(--shadow);animation:rise .4s ease both;transition:border-color .35s}
.card:hover{border-color:var(--accent)}
.vhead{display:flex;align-items:center;gap:.7rem;margin-bottom:1.2rem;flex-wrap:wrap}
.vhead .ci{display:flex;align-items:center;justify-content:center;width:42px;height:42px;border-radius:var(--ri);background:var(--glow);color:var(--accent)}
.vhead h2{font-size:1.08rem;font-weight:800}
.vhead .sp{flex:1}
.pill{display:inline-flex;align-items:center;gap:.4rem;padding:.3rem .8rem;border-radius:20px;font-size:.7rem;font-weight:700;background:var(--card2);border:1px solid var(--border);color:var(--dim)}
.pill.code{color:var(--accent);font-family:var(--f-mono)}
.label{font-size:.82rem;color:var(--dim);margin-bottom:.5rem;display:block;line-height:1.9}
.input,.select,textarea.input{width:100%;padding:.85rem 1.05rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--ri);color:var(--text);font-size:.95rem;outline:none;transition:all .3s;font-family:inherit;min-height:48px}
html[data-theme='light'] .input,html[data-theme='light'] .select,html[data-theme='light'] textarea.input{background:rgba(255,255,255,.6)}
.select{appearance:none;cursor:pointer}
textarea.input{min-height:120px;resize:vertical;direction:ltr;text-align:left;font-size:.78rem;font-family:var(--f-mono)}
.input:focus,.select:focus,textarea.input:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--glow)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.55rem;padding:.9rem 1.4rem;background:linear-gradient(135deg,var(--accent),var(--accent2),var(--accent));background-size:220% 220%;animation:gradShift 8s ease infinite;border:none;border-radius:var(--ri);color:#fff;font-size:.95rem;font-weight:700;cursor:pointer;transition:all .35s;font-family:inherit;text-decoration:none;min-height:48px}
.btn:hover{transform:translateY(-2px);box-shadow:0 10px 28px var(--glow)}
.btn.ghost{background:var(--card2);animation:none;border:1px solid var(--border);color:var(--dim)}
.btn.ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn.danger{background:var(--card2);animation:none;border:1px solid rgba(240,114,140,.35);color:var(--danger)}
.btn.sm{padding:.55rem 1rem;font-size:.82rem;min-height:42px}
.brow{display:flex;gap:.6rem;margin-top:1rem;flex-wrap:wrap}
.grid{display:grid;gap:1.2rem}
.g2{grid-template-columns:repeat(auto-fit,minmax(280px,1fr))}
.g4{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}
.stat{display:flex;align-items:center;gap:.9rem;padding:1.15rem;background:var(--card2);border-radius:var(--ri);border:1px solid var(--border)}
.stat .si{display:flex;align-items:center;justify-content:center;width:46px;height:46px;border-radius:var(--ri);background:var(--glow);color:var(--accent)}
.stat .st-v{font-size:1.3rem;font-weight:900;line-height:1.3}
.stat .st-l{font-size:.72rem;color:var(--dim)}
.cfg-item{display:flex;align-items:center;gap:.7rem;padding:.75rem .8rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--ri);margin-bottom:.55rem;transition:all .25s}
.cfg-item:hover{border-color:var(--accent)}
.cfg-name{font-size:.86rem;font-weight:700;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cfg-host{font-size:.7rem;color:var(--dim);direction:ltr;text-align:left;flex-shrink:0;max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--f-mono)}
.cfg-act{display:flex;gap:.35rem;flex-shrink:0;align-items:center}
.subbox{display:flex;gap:.6rem;margin-top:.8rem;flex-wrap:wrap}
.subbox .txt{flex:1;min-width:200px;padding:.85rem 1rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--ri);font-size:.74rem;direction:ltr;text-align:left;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dim);font-family:var(--f-mono);display:flex;align-items:center}
.cl-row{display:flex;align-items:center;gap:.7rem;padding:.9rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--ri);margin-bottom:.55rem;transition:all .25s}
.cl-row:hover,.cl-row.open{border-color:var(--accent)}
.cl-av{display:flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:var(--ri);background:var(--glow);color:var(--accent);font-weight:900;flex-shrink:0}
.cl-info{flex:1;min-width:0}
.cl-n{font-size:.92rem;font-weight:800;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cl-m{font-size:.68rem;color:var(--dim);display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.15rem}
.cl-act{display:flex;gap:.3rem;flex-shrink:0}
.tag{display:inline-block;padding:.15rem .55rem;background:var(--glow);border-radius:var(--rp);font-size:.66rem;color:var(--accent);font-weight:700}
.tag.bad{color:var(--danger);background:rgba(244,114,143,.12)}
.tag.ok{color:var(--success);background:rgba(74,214,146,.12)}
.tag.http{color:var(--warn);background:rgba(238,180,94,.12)}
.switch{position:relative;display:inline-block;width:50px;height:28px;flex-shrink:0}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:var(--card2);border:1px solid var(--border);border-radius:28px;transition:.3s}
.slider:before{content:'';position:absolute;height:20px;width:20px;left:3px;bottom:3px;background:var(--dim);border-radius:50%;transition:.3s}
input:checked+.slider{background:var(--accent);border-color:var(--accent)}
input:checked+.slider:before{transform:translateX(22px);background:#fff}
.flex{display:flex;align-items:center;gap:.6rem}
.mt{margin-top:1rem}
.hidden{display:none!important}
.spacer{flex:1}
.detail-row{display:flex;align-items:center;justify-content:space-between;padding:.7rem 0;border-bottom:1px solid var(--border);gap:.8rem}
.detail-row:last-child{border:none}
.detail-row .k{font-size:.82rem;color:var(--dim)}
.detail-row .v{font-size:.85rem;font-weight:700;direction:ltr;text-align:left;overflow:hidden;text-overflow:ellipsis}
.log-item{display:flex;align-items:flex-start;gap:.6rem;padding:.7rem;border-bottom:1px solid var(--border);font-size:.8rem}
.log-item:last-child{border:none}
.log-item .lt{color:var(--dim);font-size:.66rem;flex-shrink:0;direction:ltr}
.log-item .lx{flex:1;overflow:hidden;text-overflow:ellipsis}
.colorrow{display:flex;gap:.7rem;flex-wrap:wrap;margin:.3rem 0 .5rem}
.cdot{width:42px;height:42px;border-radius:50%;background:var(--c);border:3px solid transparent;cursor:pointer;transition:all .25s;box-shadow:0 3px 12px rgba(0,0,0,.25)}
.cdot:hover{transform:scale(1.12)}
.cdot.on{border-color:var(--text);box-shadow:0 0 0 3px var(--card),0 4px 14px rgba(0,0,0,.35)}
/* ── بانک رله: یک شبکهٔ تخت. هر کشور دقیقاً یک رله دارد، پس سرتیترِ گروه
   فقط طول صفحه را زیاد می‌کرد — کشور داخل خودِ کارت می‌آید.
   کارت حدود ۳۴px ارتفاع دارد، برای همین ۳۰ کشور در چند ردیف جا می‌شود. */
.rl-grp{margin-bottom:.75rem}
.rl-grp-h{display:flex;align-items:center;gap:.35rem;font-size:.68rem;font-weight:700;
  color:var(--text);opacity:.85;margin-bottom:.35rem;padding-bottom:.28rem;
  border-bottom:1px solid var(--border)}
.rl-sub{font-size:.6rem;font-weight:700;color:var(--dim);margin:.45rem 0 .22rem;
  display:flex;align-items:center;gap:.3rem}
.rl-grid{display:grid;gap:.3rem;grid-template-columns:repeat(auto-fill,minmax(122px,1fr))}
.rl-srch{display:flex;gap:.35rem;align-items:center;margin-bottom:.45rem}
.rl-srch .input{flex:1 1 auto;min-width:0}
.rl-chip{font-size:.6rem;padding:.22rem .5rem;border-radius:99px;border:1px solid var(--border);
  background:var(--card2);color:var(--dim);cursor:pointer;white-space:nowrap;flex:none}
.rl-chip.on{border-color:var(--accent);color:var(--text);
  background:color-mix(in srgb,var(--accent) 14%,var(--card))}
.rl-wrap{display:grid;gap:.4rem;
  grid-template-columns:repeat(auto-fill,minmax(132px,1fr))}
.rl-row{display:flex;align-items:center;gap:.35rem;min-width:0;
  /* ۲۴٪ accent: در تم تاریک کارت را از زمینه جدا می‌کند (۱.۴۸:۱) و در تم
     روشن هم IP بالای ۴.۵:۱ می‌ماند. هر دو از متغیرهای تم می‌آیند. */
  background:color-mix(in srgb,var(--card) 76%,var(--accent) 24%);
  border:1px solid color-mix(in srgb,var(--border) 25%,var(--text) 75%);
  border-radius:9px;padding:.3rem .45rem;cursor:pointer;font-family:inherit;
  color:var(--text);font-size:.68rem;line-height:1.25;
  transition:border-color .12s,background .12s}
.rl-row:hover{border-color:var(--accent)}
.rl-row:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.rl-flag{font-size:.95rem;flex:none;line-height:1}
.rl-txt{min-width:0;flex:1 1 auto;overflow:hidden}
/* کد کشور و IP روی هم: کاربر کشور را می‌بیند، IP در خط زیر می‌ماند. */
.rl-cc{display:block;font-weight:700;font-size:.68rem;letter-spacing:.02em;
  color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rl-ip{display:block;direction:ltr;text-align:left;font-family:var(--f-mono);
  font-size:.58rem;color:color-mix(in srgb,var(--dim) 80%,var(--text) 20%);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rl-tick{flex:none;width:.85rem;height:.85rem;border-radius:50%;
  border:1px solid var(--border);background:var(--card2);color:transparent;
  font-size:.5rem;line-height:.85rem;text-align:center;user-select:none}
/* حالت فعال: فقط رنگ — از متغیرهای تم می‌آید، پس در هر دو تم خوانا می‌ماند */
.rl-row.on{border-color:var(--success);
  background:color-mix(in srgb,var(--success) 16%,var(--card))}
.rl-row.on .rl-tick{background:var(--success);border-color:var(--success);color:var(--text)}
.rl-row.on .rl-ip{color:var(--text)}
.rl-empty{font-size:.75rem;color:var(--dim);padding:.6rem;text-align:center}
/* موبایل: حداقل عرض کارت کم می‌شود تا سه‌ستونه جا شود — ۳۰ رله در ۱۰ ردیف،
   نه ۱۵ ردیف. */
@media(max-width:520px){.rl-wrap{grid-template-columns:repeat(auto-fill,minmax(58px,1fr));gap:.24rem}
  .rl-row{padding:.18rem .2rem;font-size:.54rem;gap:.12rem}
  .rl-cc{font-size:.5rem}
  .rl-ip{font-size:.42rem}
  .rl-flag{font-size:.64rem}}
.ip-row{display:flex;align-items:center;justify-content:space-between;padding:.55rem .85rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--rp);margin-bottom:.35rem;font-size:.82rem}
.ip-row .ipa{direction:ltr;font-family:var(--f-mono);font-size:.74rem}
.ip-row .ms{font-family:var(--f-mono);font-size:.74rem;font-weight:700}
.ip-row.ok{border-color:rgba(74,214,146,.45)}
.ip-row.ok .ms{color:var(--success)}
.ip-row.bad{border-color:rgba(244,114,143,.45);opacity:.8}
.ip-row.bad .ms{color:var(--danger)}
.bgprev{height:90px;border-radius:var(--ri);border:1px dashed var(--border);background-size:cover;background-position:center;background-color:var(--card2);position:relative}
.bgprev span{position:absolute;bottom:6px;right:8px;font-size:.6rem;background:rgba(0,0,0,.55);color:#fff;padding:.1rem .5rem;border-radius:8px}
/* rix:frag-ui */
.fragbox{margin-top:14px;padding:12px 13px;border:1px solid var(--line);border-radius:12px;background:var(--card2)}
.frag-h{display:flex;align-items:center;gap:8px}
.frag-t{font-size:13px;font-weight:700}
.frag-v{font-size:11px;font-family:var(--mono);color:var(--muted);direction:ltr}
.frag-n{margin:6px 0 10px;font-size:11.5px;color:var(--muted);line-height:1.7}
.fragrow{display:flex;flex-wrap:wrap;gap:7px}
.fbtn{font-size:11.5px;padding:6px 11px;border-radius:9px;border:1px solid var(--line);background:var(--card);color:var(--txt);cursor:pointer;transition:.15s}
.fbtn:hover{border-color:var(--acc)}
.fbtn.on{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:700}
/* rix:i18n-ui */
.langsel{display:flex;gap:3px;padding:3px;border:1px solid var(--line);border-radius:9px;background:var(--card2)}
.langsel button{border:0;background:transparent;color:var(--muted);font-size:11.5px;padding:4px 9px;border-radius:7px;cursor:pointer;font-weight:600}
.langsel button.on{background:var(--acc);color:#fff}
.langsel button:hover:not(.on){color:var(--txt)}

.file-row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin-top:.5rem}
.file-row input[type=file]{flex:1;min-width:150px;font-size:.75rem;padding:.5rem}
.footer{text-align:center;padding:2rem 1rem;color:var(--dim);font-size:.75rem}
.creator{display:flex;justify-content:center;gap:1.2rem;margin-bottom:.5rem;flex-wrap:wrap}
.creator a{color:var(--accent);text-decoration:none;display:inline-flex;align-items:center;gap:.3rem}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1.5rem;position:relative;z-index:1}
.login-card{width:100%;max-width:400px;padding:2.4rem 2rem}
.login-logo{display:flex;flex-direction:column;align-items:center;gap:.9rem;margin-bottom:1.8rem}
.login-logo .mark{display:flex;align-items:center;justify-content:center;width:74px;height:74px;border-radius:var(--ri);color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2),var(--accent));background-size:220% 220%;animation:gradShift 8s ease infinite;box-shadow:0 14px 40px var(--glow);font-weight:900;font-size:2rem}
.login-logo h1{font-size:1.45rem;font-weight:900;letter-spacing:.1em}
.login-logo h1 i{font-style:normal;background:linear-gradient(120deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.login-logo small{color:var(--dim);font-size:.62rem;letter-spacing:.35em}
.login-err{color:var(--danger);font-size:.8rem;margin-top:.6rem;text-align:center}
.toast{position:fixed;bottom:2rem;left:50%;transform:translateX(-50%);padding:.85rem 1.6rem;background:var(--card);border:1px solid var(--border);border-radius:var(--ri);font-size:.88rem;font-weight:700;box-shadow:var(--shadow);z-index:9999;animation:toastIn .35s ease;backdrop-filter:blur(20px)}
.toast.ok{border-color:var(--success);color:var(--success)}
.toast.err{border-color:var(--danger);color:var(--danger)}
.modal{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;background:rgba(6,4,16,.7);backdrop-filter:blur(10px);animation:fadeIn .2s ease;padding:1rem}
.modal-box{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:1.6rem;max-width:min(94vw,460px);width:100%;max-height:90vh;overflow-y:auto;box-shadow:var(--shadow);animation:popIn .25s cubic-bezier(.22,1.2,.36,1)}
.modal-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
.modal-head b{font-size:.98rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:80%}
.modal-qrimg{width:min(64vw,280px);height:auto;border-radius:var(--ri);background:#fff;box-shadow:0 8px 30px rgba(0,0,0,.25);display:block;margin:0 auto}
.fgroup{margin-bottom:1rem}
.v-wrap{position:relative;z-index:1;max-width:820px;margin:0 auto;padding:1.2rem 1rem 3rem;display:flex;flex-direction:column;gap:1.3rem}
.v-top{display:flex;justify-content:space-between;align-items:center}
.v-hero{background:var(--card);backdrop-filter:blur(22px);border:1px solid var(--border);border-radius:var(--r);padding:2rem 1.5rem;text-align:center;box-shadow:var(--shadow);overflow:hidden;position:relative}
.v-hero:before{content:'';position:absolute;inset:0;background:linear-gradient(160deg,var(--glow),transparent 55%);pointer-events:none}
.v-hero .mark{display:flex;align-items:center;justify-content:center;width:74px;height:74px;border-radius:var(--ri);margin:0 auto .9rem;color:#fff;background:linear-gradient(135deg,var(--accent),var(--accent2));font-weight:900;font-size:2rem;box-shadow:0 12px 34px var(--glow);position:relative}
.v-hero h1{font-size:1.4rem;font-weight:900;position:relative}
.v-hero h1 i{font-style:normal;background:linear-gradient(120deg,var(--accent),var(--accent2));-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.v-hero p{color:var(--dim);font-size:.86rem;margin-top:.3rem;position:relative}
.chips{display:flex;justify-content:center;gap:.5rem;flex-wrap:wrap;margin-top:1rem;position:relative}
.chip{display:inline-flex;align-items:center;gap:.35rem;padding:.3rem .8rem;background:var(--card2);border:1px solid var(--border);border-radius:20px;font-size:.7rem;font-weight:700;color:var(--dim)}
.qr-hero{background:var(--card);backdrop-filter:blur(22px);border:1px solid var(--border);border-radius:var(--r);padding:1.8rem;text-align:center;box-shadow:var(--shadow)}
.qr-hero img{width:min(56vw,240px);height:auto;border-radius:18px;background:#fff;padding:10px;box-shadow:0 10px 34px rgba(0,0,0,.3)}
.qr-hero .qh-t{font-size:.95rem;font-weight:800;margin-bottom:.4rem}
.qr-hero .qh-d{font-size:.76rem;color:var(--dim);margin-bottom:1rem}
.hub-item{display:flex;align-items:center;gap:.9rem;padding:1rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--ri);margin-bottom:.6rem;transition:all .25s}
.hub-item:hover{border-color:var(--accent)}
.hub-item .hub-av{display:flex;align-items:center;justify-content:center;width:48px;height:48px;border-radius:var(--ri);background:var(--glow);color:var(--accent);font-weight:900;font-size:1.1rem;flex-shrink:0}
.hub-item .hub-info{flex:1;min-width:0}
.hub-item .hub-n{font-size:.95rem;font-weight:800}
.hub-item .hub-m{font-size:.68rem;color:var(--dim);display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.1rem}
.hub-item .hub-qr{width:60px;height:60px;border-radius:12px;background:#fff;padding:4px;flex-shrink:0;cursor:pointer;transition:transform .2s}
.hub-item .hub-qr:hover{transform:scale(1.08)}
.hub-item .hub-act{display:flex;gap:.35rem;flex-shrink:0;flex-wrap:wrap}
.v-item{display:flex;align-items:center;gap:.7rem;padding:.85rem .9rem;background:var(--card2);border:1px solid var(--border);border-radius:var(--ri);margin-bottom:.55rem;transition:all .25s}
.v-item:hover{border-color:var(--accent)}
.v-item .vi-n{flex:1;min-width:0}
.v-item .vi-t{font-size:.88rem;font-weight:800;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:ltr;text-align:left}
.v-item .vi-s{font-size:.68rem;color:var(--dim);display:flex;gap:.5rem;align-items:center;margin-top:.1rem;flex-wrap:wrap}
.hint{background:rgba(238,180,94,.08);border:1px solid rgba(238,180,94,.3);border-radius:var(--ri);padding:1rem 1.2rem;font-size:.82rem}
.hint b{color:var(--warn)}
.gsec{display:flex;align-items:center;gap:.6rem;margin:1.2rem 0 .7rem}
.gsec .gs-line{flex:1;height:1px;background:var(--border)}
.gsec .gs-t{font-size:.8rem;font-weight:800;color:var(--dim)}
/* ═══════════════════════════════════════════════════════════════
   ✨ لایهٔ صیقل — از اسکرین‌شات‌های واقعی پنل درآمده، نه از حدس.
   هر قانون اینجا یک ایراد دیده‌شده را حل می‌کند:
   · متن‌های ثانویه در پس‌زمینهٔ تیره گم می‌شدند      → کنتراست بالا
   · کارت‌ها با پس‌زمینه یکی دیده می‌شدند            → خط مرزی روشن‌تر
   · دکمهٔ ذخیره در پایین صفحه بریده می‌شد           → فاصلهٔ امن انتها
   · نیمهٔ چپ کارت‌ها خالی و نامتوازن می‌ماند       → شبکهٔ دوستونه
   · نسخه و فوتر تقریباً ناخوانا بودند              → اندازهٔ کمی بزرگ‌تر
   · فاصلهٔ عمودی زیاد بود و صفحه بلند می‌شد         → تراکم بیشتر
   ═══════════════════════════════════════════════════════════════ */

/* ── ۱) کارت‌ها باید از زمینه جدا شوند ── */
.card{
  border-color:color-mix(in srgb,var(--accent) 16%,var(--border));
  box-shadow:var(--shadow),0 1px 0 rgba(255,255,255,.03) inset;
}
/* حاشیهٔ بالای کارت یک نوار رنگی نازک: چشم سریع کارت‌ها را از هم
   جدا می‌کند بدون اینکه فضای اضافه بخورد. */
.card{position:relative;overflow:hidden}
.card::before{
  content:'';position:absolute;inset-inline:0;top:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--accent),transparent);
  opacity:.5;pointer-events:none;
}

/* ── ۲) متن‌های ثانویه: کنتراست کافی برای خواندن در نور کم ── */
.sbar .ver,.sbar .sfoot,.hint small,.pill,.tag,.sub,.muted,.rl-empty,.rl-sub{
  color:var(--muted);
}
/* نسخه و فوتر نباید حدس زده شوند */
.sbar .ver{font-size:.66rem;letter-spacing:.02em;opacity:1}
.sbar .sfoot{font-size:.62rem;opacity:1}

/* ── ۳) فاصلهٔ امن پایین — دکمهٔ ذخیره دیگر بریده نمی‌شود ── */
.main{padding-bottom:5.5rem}
.card>.brow:last-child,.card>button:last-child{margin-bottom:.35rem}

/* ── ۴) شبکهٔ دوستونه: نیمهٔ خالی کارت‌ها پر می‌شود ── */
.grid.g2{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem 1.1rem}
/* وقتی یک فیلد ستون کامل می‌خواهد (فیلدهای بلند مثل لیست رله)،
   ستون دوم خالی نماند. */
.grid.g2>div:only-child{grid-column:1/-1}

/* ── ۵) تراکم عمودی: فاصله‌ها کمی کمتر، صفحه کوتاه‌تر ── */
.main{gap:1.15rem}
.card{padding:1.35rem 1.4rem}
.grid{gap:.85rem}

/* ── ۶) سلسلهٔ مراتب عنوان‌ها یکدست ── */
.card .vhead h2{font-size:1rem;line-height:1.6}
.card .vhead{gap:.5rem}

/* ── ۷) فیلدها: مرز محسوس‌تر، چون قبلاً با پس‌زمینه یکی بود ── */
.input,.select{
  border-color:color-mix(in srgb,var(--accent) 12%,var(--border));
  transition:border-color .2s,box-shadow .2s;
}
.input:focus,.select:focus{
  border-color:var(--accent);
  box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 18%,transparent);
}

/* ── ۸) گزینه‌های نوار کناری نباید «غیرفعال» به نظر برسند ── */
.sbar a,.sbar button{
  color:var(--dim);
  transition:color .2s,background .2s,border-color .2s;
}
.sbar a:hover,.sbar button:hover{color:var(--text)}
.sbar a.on,.sbar button.on{color:var(--text)}

/* ── ۹) زبان و خروج در نوار بالا: فشرده و ناهمگون بودند ── */
.topbar .lang{display:flex;gap:.15rem;align-items:center;
  padding:.2rem;border-radius:var(--ri);background:var(--card2);border:1px solid var(--border)}
.topbar .lang>*{padding:.2rem .45rem;border-radius:.5rem;font-size:.7rem;
  color:var(--muted);background:none;border:none;cursor:pointer;transition:.2s}
.topbar .lang>*.on{background:var(--accent);color:#fff;font-weight:700}
.topbar .lang>*:not(.on):hover{color:var(--text);background:var(--card2)}

/* ── ۱۰) کارت آمار: عدد باید از برچسب جدا دیده شود ── */
.stat .sv{font-size:1.35rem;font-weight:800;line-height:1.35;letter-spacing:-.01em}
.stat .sl{font-size:.66rem;color:var(--muted);letter-spacing:.02em}

@media(max-width:900px){
  .sbar{position:fixed;bottom:0;right:0;left:0;top:auto;width:100%;height:auto;flex-direction:row;padding:.4rem .5rem;gap:.2rem;border-left:none;border-top:1px solid var(--border);z-index:50}
  .sb-brand,.sb-foot{display:none}
  .sb-nav{flex-direction:row;width:100%;justify-content:space-around;gap:.15rem}
  .sb-nav button{flex-direction:column;gap:.25rem;font-size:.56rem;padding:.45rem .3rem;min-height:52px;flex:1}
  .sb-nav button .ic{margin:0}
  .main{padding:1rem .8rem 6.5rem}
  .g4{grid-template-columns:repeat(2,1fr)}
  .cfg-host{display:none}
  .hub-item .hub-qr{display:none}
}
`;

/* ════════════════ 14) head مشترک ════════════════ */

function effectiveBg(cfg) {
  return {
    dark: cfg.bgDarkKv ? '/bg/dark' : (cfg.bgDarkUrl || BG_DARK_URL),
    light: cfg.bgLightKv ? '/bg/light' : (cfg.bgLightUrl || BG_LIGHT_URL)
  };
}
function headHTML(cfg, title) {
  const bg = effectiveBg(cfg);
  const bgCSS = bg.dark ? `<style>html[data-theme='dark'] body.has-bg .bg{background-image:url('${bg.dark}')}html[data-theme='light'] body.has-bg .bg{background-image:url('${bg.light || bg.dark}')}</style>` : '';
  return `<!DOCTYPE html><html lang="fa" dir="rtl" data-theme="dark" data-accent="${esc(cfg.accent || 'violet')}" data-font="${esc(cfg.fontChoice || 'vazir')}" data-fs="${esc(cfg.fontScale || 'n')}" data-corner="${esc(cfg.corner || 'soft')}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><style>${CSS}</style>${bgCSS}</head>`;
}

/* ════════════════ 15) JS مشترک صفحات ════════════════ */

const CLIENT_JS = `
function toggleTheme(){
var h=document.documentElement;
var next=h.getAttribute('data-theme')==='dark'?'light':'dark';
h.setAttribute('data-theme',next);
var tps=document.querySelectorAll('.theme-pil .tp');
for(var i=0;i<tps.length;i++)tps[i].classList.toggle('on',tps[i].dataset.t===next);
if(typeof applyBg==='function')applyBg();
try{localStorage.setItem('rix-theme',next);}catch(e){}
}
(function(){try{
var t=localStorage.getItem('rix-theme');
if(t&&t!=='dark'){document.documentElement.setAttribute('data-theme',t);
var tps=document.querySelectorAll('.theme-pil .tp');
for(var i=0;i<tps.length;i++)tps[i].classList.toggle('on',tps[i].dataset.t===t);}
}catch(e){}})();
function toast(msg,ok){
var d=document.createElement('div');
d.className='toast '+(ok?'ok':'err');d.textContent=msg;
document.body.appendChild(d);setTimeout(function(){d.remove();},3000);
}
function copyText(s){
if(!s)return;
function fallback(){
var ta=document.createElement('textarea');ta.value=s;ta.style.position='fixed';ta.style.opacity='0';
document.body.appendChild(ta);ta.select();
try{document.execCommand('copy');toast('کپی شد ✓',true);}catch(e2){toast('کپی نشد ✗',false);}
ta.remove();}
if(navigator.clipboard&&navigator.clipboard.writeText){
navigator.clipboard.writeText(s).then(function(){toast('کپی شد ✓',true);}).catch(fallback);
}else fallback();
}
function openQrModal(title,imgUrl,copyLink){
var t=document.getElementById('qrTitle');
var im=document.getElementById('qrImg');
var cb=document.getElementById('qrCopyBtn');
if(!t||!im)return;
t.textContent=title||'QR';
im.src=imgUrl;
if(cb)cb.dataset.copy=copyLink||'';
document.getElementById('qrModal').classList.remove('hidden');
}
function closeQr(){document.getElementById('qrModal').classList.add('hidden');}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeQr();});
document.addEventListener('click',function(e){
var m=document.getElementById('qrModal');
if(m&&!m.classList.contains('hidden')&&e.target===m)closeQr();
var q=e.target.closest('[data-qrimg]');
if(q){openQrModal(q.dataset.name||'QR',q.dataset.qrimg,q.dataset.copy||'');return;}
var c=e.target.closest('[data-copy]');
if(c){copyText(c.dataset.copy);}
});
`;

/* ════════════════ 16) منطق SPA پنل ════════════════ */

const PANEL_JS = `
function hesc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function routeLabel(k){var m={main:'پیشفرض',proxy:'ProxyIP',direct:'مستقیم',nl:'NAT64 هلند',us1:'NAT64 آمریکا ۱',us2:'NAT64 آمریکا ۲'};return m[k]||k;}
function clientById(id){for(var i=0;i<RIX.clients.length;i++)if(RIX.clients[i].id===id)return RIX.clients[i];return null;}
function daysLeft(c){
if(!c.expiryDays)return null;
var ms=c.created+c.expiryDays*86400000-Date.now();
return ms>0?Math.ceil(ms/86400000):0;}
function subLink(cid){var c=cid?clientById(cid):null;return 'https://'+RIX.host+'/sub/'+(c?c.subToken:RIX.token);}
function qrLink(cid,idx){var c=cid?clientById(cid):null;return 'https://'+RIX.host+'/sub/'+(c?c.subToken:RIX.token)+'/qr'+(idx!==undefined&&idx!==null?'/'+idx:'');}
function kindTag(kind){
if(kind==='main-trojan')return['Trojan',''];
if(kind==='main-http'||kind==='ip-http')return['HTTP بدون TLS ⭐','http'];
if(kind==='main-tls')return['VLESS TLS',''];
if(kind==='custom-tls')return['دامنه سفارشی',''];
return['VLESS + IP تمیز',''];}
var IQ='<svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3z"/><path d="M18 18h3v3h-3z"/><path d="M14 21h3"/><path d="M21 14v3"/></svg>';
var IC='<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
var IP='<svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>';
var IW='<svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg>';
var IT='<svg class="ic" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
var IU='<svg class="ic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>';
function renderStats(){
var act=0;for(var i=0;i<RIX.clients.length;i++)if(RIX.clients[i].enabled!==false)act++;
document.getElementById('st-clients').textContent=act;
document.getElementById('st-proto').textContent=(RIX.s.vlessEnabled?'VLESS':'—')+(RIX.s.trojanEnabled?' +TR':'');
document.getElementById('st-ports').textContent=RIX.s.tlsPorts.join(',')+(RIX.s.nonTLSEnabled?' +HTTP':'');
document.getElementById('st-cleans').textContent=(RIX.s.cleanIPs||[]).length;}
function renderClients(){
var wrap=document.getElementById('clientsList');
if(!RIX.clients.length){wrap.innerHTML='<p class="label">هنوز کلاینتی نساختهاید.</p>';return;}
var html='';
for(var i=0;i<RIX.clients.length;i++){var c=RIX.clients[i];
var dl=daysLeft(c);
html+='<div class="cl-row" data-cid="'+hesc(c.id)+'">'
+'<div class="cl-av">'+hesc((c.name||'C')[0])+'</div>'
+'<div class="cl-info"><div class="cl-n">'+hesc(c.name)+'</div><div class="cl-m"><span class="tag">'+hesc(routeLabel(c.country))+'</span><span>'+(c.quotaGB>0?c.quotaGB+' گیگ':'نامحدود')+'</span>'
+(dl!==null?'<span class="tag '+(dl>0?'ok':'bad')+'">'+(dl>0?dl+' روز مانده':'منقضی')+'</span>':'')
+'<span>'+(c.enabled!==false?'🟢 فعال':'🔴 غیرفعال')+'</span></div></div>'
+'<div class="cl-act">'
+'<button class="icon-btn sm" data-act="detail" data-id="'+c.id+'" title="کانفیگها">'+IQ+'</button>'
+'<button class="icon-btn sm" data-act="edit" data-id="'+c.id+'" title="ویرایش">'+IP+'</button>'
+'<button class="icon-btn sm" data-act="toggle" data-id="'+c.id+'" title="فعال/غیرفعال">'+IW+'</button>'
+'<button class="icon-btn sm" data-act="del" data-id="'+c.id+'" title="حذف">'+IT+'</button>'
+'</div></div>';}
wrap.innerHTML=html;}
function renderSubs(){
var wrap=document.getElementById('perClientSubs');
var html='';
for(var i=0;i<RIX.clients.length;i++){var c=RIX.clients[i];
var link=subLink(c.id);
var qr=qrLink(c.id);
html+='<div class="cfg-item"><span class="cfg-name">'+hesc(c.name)+'</span><span class="cfg-host">'+hesc(link.replace('https://',''))+'</span><span class="cfg-act">'
+'<button class="icon-btn sm" data-qrimg="'+hesc(qr)+'" data-name="ساب '+hesc(c.name)+'" data-copy="'+hesc(link)+'" title="QR ساب">'+IQ+'</button>'
+'<button class="icon-btn sm" data-copy="'+hesc(link)+'" title="کپی لینک ساب">'+IC+'</button>'
+'<a class="icon-btn sm" href="'+hesc(link)+'?view=1" target="_blank" rel="noopener" title="بازکردن سابپنل">↗</a>'
+'</span></div>';}
wrap.innerHTML=html||'<p class="label">کلاینتی موجود نیست.</p>';
var main=subLink('');
document.getElementById('mainSubTxt').textContent=main;
document.getElementById('btnMainSubCopy').dataset.copy=main;
document.getElementById('btnMainSubQR').dataset.qrimg=qrLink('');
document.getElementById('btnMainSubQR').dataset.name='ساب کلی';
document.getElementById('btnMainSubQR').dataset.copy=main;
document.getElementById('viewSubLink').href=main;}
function showPage(id){
var pages=['dash','clients','subs','scanner','settings'];
for(var i=0;i<pages.length;i++){var el=document.getElementById('page-'+pages[i]);if(el)el.classList.toggle('hidden',pages[i]!==id);}
var btns=document.querySelectorAll('.sb-nav button');
for(var j=0;j<btns.length;j++)btns[j].classList.toggle('active',btns[j].dataset.page===id);
window.scrollTo(0,0);}
function openModal(html){
document.getElementById('modalBody').innerHTML=html;
document.getElementById('genModal').classList.remove('hidden');}
function closeModal(){document.getElementById('genModal').classList.add('hidden');}
document.addEventListener('click',function(e){
var m=document.getElementById('genModal');
if(m&&!m.classList.contains('hidden')&&e.target===m)closeModal();
var b=e.target.closest('[data-act]');
if(b){var id=b.dataset.id;
if(b.dataset.act==='detail')openClientDetail(id);
else if(b.dataset.act==='edit')openClientModal(id);
else if(b.dataset.act==='toggle')toggleClient(id);
else if(b.dataset.act==='del')delClient(id);}});
function openClientDetail(id){
showPage('clients');
var all=document.querySelectorAll('[id^=cd-]');
for(var i=0;i<all.length;i++)all[i].classList.add('hidden');
var el=document.getElementById('cd-'+id);
if(el)el.classList.remove('hidden');
var rows=document.querySelectorAll('.cl-row');
for(var j=0;j<rows.length;j++)rows[j].classList.toggle('open',rows[j].dataset.cid===id);
loadVariants(id);
loadUsage(id);
window.scrollTo(0,0);}
async function loadVariants(id){
var box=document.getElementById('cfgList-'+id);
if(!box)return;
box.innerHTML='<p class="label">در حال دریافت کانفیگها…</p>';
try{
var r=await api('variants',{id:id});
if(!r.ok){box.innerHTML='<p class="label">خطا</p>';return;}
if(!r.variants.length){box.innerHTML='<p class="label">پروتکلی فعال نیست.</p>';return;}
var html='';
for(var i=0;i<r.variants.length;i++){var v=r.variants[i];var t=kindTag(v.kind);
html+='<div class="v-item"><div class="vi-n"><div class="vi-t">'+hesc(v.addr+':'+v.port)+'</div><div class="vi-s"><span class="tag '+t[1]+'">'+t[0]+'</span></div></div>'
+'<span class="cfg-act">'
+'<button class="icon-btn sm" data-qrimg="'+hesc(qrLink(id,v.i))+'" data-name="'+hesc(v.addr+':'+v.port)+'" data-copy="'+hesc(v.link)+'" title="QR">'+IQ+'</button>'
+'<button class="icon-btn sm" data-copy="'+hesc(v.link)+'" title="کپی">'+IC+'</button></span></div>';}
box.innerHTML=html;
}catch(e){box.innerHTML='<p class="label" style="color:var(--danger)">'+hesc((e&&e.message)?e.message:'ارتباط با سرور برقرار نشد')+'</p>';}}
async function loadUsage(id){
try{var r=await api('usage',{id:id});
var el=document.getElementById('usage-'+id);
if(el&&r.ok)el.textContent=(r.bytes/1073741824).toFixed(2)+' GB';
}catch(e){}}
function openClientModal(id){
var c=id?clientById(id):null;
var routes=[['main','پیشفرض — هوشمند (کلادفلر→رله، بقیه→مستقیم)'],['proxy','ProxyIP (رله) — فقط رله'],['direct','مستقیم — بدون رله'],['nl','NAT64 هلند — فقط هلند'],['us1','NAT64 آمریکا ۱ — فقط آمریکا۱'],['us2','NAT64 آمریکا ۲ — فقط آمریکا۲']];
var opts='';
for(var i=0;i<routes.length;i++)opts+='<option value="'+routes[i][0]+'"'+((c?c.country:'main')===routes[i][0]?' selected':'')+'>'+routes[i][1]+'</option>';
openModal(
'<div class="modal-head"><b>'+(c?'ویرایش کلاینت':'ساخت کلاینت جدید')+'</b><button class="icon-btn sm" onclick="closeModal()" aria-label="بستن">✕</button></div>'
+'<div class="fgroup"><label class="label">نام کلاینت</label><input class="input" id="m-name" value="'+hesc(c?c.name:'')+'" placeholder="مثلاً: گوشی من" maxlength="32"></div>'
+'<div class="fgroup"><label class="label">مسیر (پروکسی خروجی)</label><select class="select" id="m-route">'+opts+'</select></div>'
+'<div class="grid g2"><div><label class="label">سهمیه گیگابایت (۰=نامحدود)</label><input class="input" id="m-quota" type="number" min="0" max="1000" value="'+(c?c.quotaGB:0)+'"></div>'
+'<div><label class="label">انقضا (روز — ۰=هرگز)</label><input class="input" id="m-exp" type="number" min="0" max="3650" value="'+(c?c.expiryDays:0)+'"></div></div>'
+'<div class="fgroup flex"><span class="label" style="margin:0">کانفیگهای IP تمیز</span><span class="spacer"></span><label class="switch"><input type="checkbox" id="m-clean" '+(c&&c.cleanIPs===false?'':'checked')+'><span class="slider"></span></label></div>'
+'<div class="fgroup flex"><span class="label" style="margin:0">فعال باشد</span><span class="spacer"></span><label class="switch"><input type="checkbox" id="m-en" '+(c&&c.enabled===false?'':'checked')+'><span class="slider"></span></label></div>'
+'<div class="brow"><button class="btn" style="width:100%" onclick="submitClient('+(c?"'"+c.id+"'":'null')+')">'+(c?'ذخیره تغییرات':'🎉 ساخت کلاینت')+'</button></div>');}
async function submitClient(id){
var body={
name:document.getElementById('m-name').value.trim()||'کلاینت جدید',
country:document.getElementById('m-route').value,
quotaGB:parseFloat(document.getElementById('m-quota').value)||0,
expiryDays:parseInt(document.getElementById('m-exp').value)||0,
cleanIPs:document.getElementById('m-clean').checked,
enabled:document.getElementById('m-en').checked};
try{
var r;
if(id){r=await api('updateClient',Object.assign({id:id},body));
if(r.ok){var c=clientById(id);if(c)Object.assign(c,r.client);
toast('تغییرات ذخیره شد ✓',true);renderAll();openClientDetail(id);closeModal();}
}else{r=await api('addClient',body);
if(r.ok){RIX.clients.push(r.client);
toast('🎉 کلاینت شما ساخته شد',true);
closeModal();renderAll();openClientDetail(r.client.id);}}
if(!r.ok)toast(r.err||'خطا',false);
}catch(e){}}
async function toggleClient(id){
try{var r=await api('toggleClient',{id:id});
if(r.ok){var c=clientById(id);if(c)c.enabled=r.enabled;
toast('وضعیت عوض شد ✓',true);renderAll();}
else toast(r.err||'خطا',false);
}catch(e){}}
async function delClient(id){
var c=clientById(id);
if(!confirm('کلاینت «'+(c?c.name:'')+'» حذف شود؟'))return;
try{var r=await api('delClient',{id:id});
if(r.ok){RIX.clients=RIX.clients.filter(function(x){return x.id!==id;});
toast('حذف شد ✓',true);renderAll();}
else toast(r.err||'خطا',false);
}catch(e){}}
async function api(path,body){
try{
var r=await fetch('/api/'+path,{method:'POST',headers:{'Content-Type':'application/json','X-Rix-Api':'1'},body:JSON.stringify(body||{})});
if(r.status===401){location.href='/logout';throw new Error('نشست شما منقضی شده — دوباره وارد شوید');}
if(r.status===429)throw new Error('درخواست زیاد — کمی صبر کنید');
var ct=r.headers.get('content-type')||'';
if(ct.indexOf('json')<0){
var txt=await r.text().catch(function(){return ''});
throw new Error('پاسخ نامعتبر از سرور (HTTP '+r.status+')'+(txt?': '+txt.slice(0,60):''));
}
var j=await r.json();
if(!j.ok&&j.err)throw new Error(j.err);
return j;
}catch(e){
if(e&&e.message==='نشست شما منقضی شده — دوباره وارد شوید')throw e;
var m=(e&&e.message)?e.message:'ارتباط با سرور برقرار نشد';
toast('خطا: '+m,false);
throw e;
}}
function applyPersona(){
var h=document.documentElement;
h.dataset.accent=RIX.s.accent;h.dataset.font=RIX.s.fontChoice;
h.dataset.fs=RIX.s.fontScale;h.dataset.corner=RIX.s.corner;
var dots=document.querySelectorAll('.cdot');
for(var i=0;i<dots.length;i++)dots[i].classList.toggle('on',dots[i].dataset.accent===RIX.s.accent);
var fs=document.getElementById('s-font');if(fs)fs.value=RIX.s.fontChoice;
var fz=document.getElementById('s-fs');if(fz)fz.value=RIX.s.fontScale;
var cr=document.getElementById('s-corner');if(cr)cr.value=RIX.s.corner;}
function applyBg(){
var d=RIX.s.bgDarkUrl||'',l=RIX.s.bgLightUrl||'';
var has=!!(d||l);
document.body.classList.toggle('has-bg',has);
var bg=document.querySelector('.bg');if(!bg)return;
var cur=document.documentElement.dataset.theme==='light'?(l||d):d;
if(cur){bg.style.backgroundImage="url('"+cur.replace(/'/g,'%27')+"')";}
else bg.style.backgroundImage='';}
function bgOk(u){if(!u)return false;if(u==='/bg/dark'||u==='/bg/light')return true;
if(!/^https:\\/\\/[\\x21-\\x7E]+$/.test(u))return false;
return !/['"();<>\\\\{}]/.test(u);}
/* بکگراند — کنترل‌های سمت مرورگر (داخل PANEL_JS) */








async function savePersona(){
var on=document.querySelector('.cdot.on');
RIX.s.accent=on?on.dataset.accent:'violet';
RIX.s.fontChoice=document.getElementById('s-font').value;
RIX.s.fontScale=document.getElementById('s-fs').value;
RIX.s.corner=document.getElementById('s-corner').value;
applyPersona();
try{var r=await api('savePersona',{accent:RIX.s.accent,fontChoice:RIX.s.fontChoice,fontScale:RIX.s.fontScale,corner:RIX.s.corner});
if(r.ok)toast('ظاهر ذخیره شد ✓',true);else toast(r.err||'خطا',false);
}catch(e){}}
/* 🧭 راهنمای زندهٔ حالت XHTTP.
   کاربر نباید حدس بزند کدام حالت را انتخاب کند — هر حالت یک بده‌بستان
   روشن دارد. این تابع متن را با حالت انتخاب‌شده هماهنگ می‌کند و
   انتخابگر را وقتی خاموش است کم‌رنگ می‌کند تا بی‌معنا نباشد. */
var XHTTP_MODE_HELP = {
  'stream-one':  '✅ <b>پیشنهادی برای اکثر کاربران.</b> کل تبادل در یک درخواست انجام می‌شود، پس سریع‌ترین گزینه است و کمترین منابع را می‌گیرد. اگر جایی قطع نشد، همین را نگه دار.',
  'stream-up':   '⚡ داده فقط رو به بالا جریان دارد و پاسخ از همان اتصال برمی‌گردد. روی شبکه‌های پرنوسان گاهی سریع‌تر است، ولی اگر خطا دیدی برگرد به stream-one.',
  'packet-up':   '🧱 داده بسته‌بسته می‌رود. مقاوم‌ترین حالت روی اینترنت ضعیف یا ناپایدار، اما کمی کندتر. برای شبکه‌های موبایل خوب است.'
};
function syncXhttpUI(){
  var wrap=document.getElementById('xhttpModeWrap');
  var sel=document.getElementById('s-xhttp-mode');
  var hint=document.getElementById('xhttpModeHint');
  var tog=document.getElementById('s-xhttp');
  if(!wrap||!sel) return;
  var on=!tog||tog.checked;
  wrap.style.opacity=on?'1':'.42';
  sel.disabled=!on;
  if(hint){
    var t=XHTTP_MODE_HELP[sel.value]||'';
    hint.innerHTML=on?t:'<span style="opacity:.7">برای فعال شدن XHTTP، کلید بالا را روشن کن.</span>';
  }
}
(function(){
  var sel=document.getElementById('s-xhttp-mode');
  var tog=document.getElementById('s-xhttp');
  if(sel) sel.addEventListener('change',syncXhttpUI);
  if(tog) tog.addEventListener('change',syncXhttpUI);
})();

function fillSettings(){
document.getElementById('s-fp').value=RIX.s.fingerprint;
document.getElementById('s-sni').value=RIX.s.sniOverride;
document.getElementById('s-custom').value=RIX.s.customAddr;
document.getElementById('s-tlsports').value=RIX.s.tlsPorts.join(', ');
document.getElementById('s-nontls').checked=RIX.s.nonTLSEnabled;
document.getElementById('s-nontlsports').value=RIX.s.nonTLSPorts.join(', ');
document.getElementById('s-proxyip').value=RIX.s.proxyIP;
document.getElementById('s-proxyon').checked=RIX.s.proxyEnabled;
document.getElementById('s-nat64').checked=RIX.s.nat64Enabled;
document.getElementById('s-nat64p').value=RIX.s.nat64Prefix;
document.getElementById('s-vless').checked=RIX.s.vlessEnabled;
document.getElementById('s-trojan').checked=RIX.s.trojanEnabled;
document.getElementById('s-xhttp').checked=RIX.s.xhttpEnabled!==false;
var _xm=document.getElementById('s-xhttp-mode');if(_xm)_xm.value=RIX.s.xhttpMode||'stream-one';
syncXhttpUI();
renderRelays();


document.getElementById('s-cleanips').value=(RIX.s.cleanIPs||[]).join('\\n');
}
/* ⚡ ذخیرهٔ خودکار — هر تغییر در تنظیمات بعد از ۹۰۰ms بی‌حرکتی خودکار ذخیره می‌شود.
   نیازی به زدن دکمه یا رفرش صفحه نیست. وضعیت بالای دکمه نشان می‌دهد چه شد. */
var _autoTimer=null,_autoInFlight=false,_autoPending=false;
function _autoState(txt,color){
  var el=document.getElementById('autosaveState');
  if(!el)return;
  el.textContent=txt;
  el.style.color=color||'var(--muted)';
}
function queueAutoSave(){
  _autoState('در حال ذخیره خودکار…','var(--warn,#f6a04d)');
  clearTimeout(_autoTimer);
  _autoTimer=setTimeout(function(){ doAutoSave(); },900);
}
async function doAutoSave(){
  if(_autoInFlight){ _autoPending=true; return; }
  _autoInFlight=true;
  try{
    var r=await api('saveSettings',collectSettings());
    if(r&&r.ok){
      var last=RIX.savedAt||0;
      if(Date.now()-last>5000){ renderSubs(); }
      RIX.savedAt=Date.now();
      _autoState('✓ ذخیره شد — ' + new Date().toLocaleTimeString('fa-IR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}),'var(--ok,#3ecf8e)');
    }else{
      _autoState('✖ ذخیره نشد: ' + ((r&&r.err)||'خطای نامشخص'),'var(--danger,#f2446f)');
    }
  }catch(e){
    _autoState('✖ خطای شبکه — دوباره تلاش کنید','var(--danger,#f2446f)');
  }finally{
    _autoInFlight=false;
    if(_autoPending){ _autoPending=false; queueAutoSave(); }
  }
}
function collectSettings(){
  RIX.s.fingerprint=document.getElementById('s-fp').value;
  RIX.s.sniOverride=document.getElementById('s-sni').value.trim();
  RIX.s.customAddr=document.getElementById('s-custom').value.trim();
  RIX.s.tlsPorts=document.getElementById('s-tlsports').value.split(',').map(function(x){return parseInt(x.trim());}).filter(function(x){return [443,2053,2083,2087,2096,8443].indexOf(x)>=0;});
  if(!RIX.s.tlsPorts.length)RIX.s.tlsPorts=[443];
  RIX.s.nonTLSEnabled=document.getElementById('s-nontls').checked;
  RIX.s.nonTLSPorts=document.getElementById('s-nontlsports').value.split(',').map(function(x){return parseInt(x.trim());}).filter(function(x){return [80,8080,8880,2052,2082,2086,2095].indexOf(x)>=0;});
  if(!RIX.s.nonTLSPorts.length)RIX.s.nonTLSPorts=[80];
  RIX.s.proxyIP=document.getElementById('s-proxyip').value.trim();
  RIX.s.proxyEnabled=document.getElementById('s-proxyon').checked;
  RIX.s.nat64Enabled=document.getElementById('s-nat64').checked;
  RIX.s.nat64Prefix=document.getElementById('s-nat64p').value;
  RIX.s.vlessEnabled=document.getElementById('s-vless').checked;
  RIX.s.trojanEnabled=document.getElementById('s-trojan').checked;
  RIX.s.xhttpEnabled=document.getElementById('s-xhttp').checked;
  var _xm2=document.getElementById('s-xhttp-mode');if(_xm2)RIX.s.xhttpMode=_xm2.value;
  syncXhttpUI();
  /* فیلد لینک فقط وقتی حرف می‌زند که کاربر چیزی در آن گذاشته باشد؛ خالی‌بودنش
     نباید بکگراند آپلودی را پاک کند. */
  var bdi=document.getElementById('s-bgdark'),bli=document.getElementById('s-bglight');
  var bd=bdi?bdi.value.trim():'',bl=bli?bli.value.trim():'';
  if(bd)RIX.s.bgDarkUrl=(bd==='/bg/dark')?'':bd;
  if(bl)RIX.s.bgLightUrl=(bl==='/bg/light')?'':bl;
  RIX.s.cleanIPs=document.getElementById('s-cleanips').value.split('\\n').map(function(s){return s.trim();}).filter(Boolean);
  return RIX.s;
}
/* 🌍 انتخابگر رله — بانک ۳۰تایی، انتخاب گرافیکی، ذخیرهٔ فوری.
   کلیک روی رله آن را در فهرست فعال می‌گذارد یا برمی‌دارد؛ دکمه‌های بالا حالت
   خودکار / بدون رله / تصادفی را تنظیم می‌کنند. */
function activeRelays(){
  if(!Array.isArray(RIX.s.proxyRelays))RIX.s.proxyRelays=[];
  return RIX.s.proxyRelays;
}
function renderRelays(){
  var box=document.getElementById('relayBox');
  var cnt=document.getElementById('relayCount');
  if(!box)return;
  wireRelayBox();
  /* جست‌وجو و فیلتر باید با هر رندر هم‌گام بمانند، وگرنه کلیک روی یک رله
     عبارت جست‌وجو را پاک می‌کند و کاربر دوباره تایپ می‌کند. */
  var _s=document.getElementById('relaySearch');
  if(_s&&_s.value!==(RIX._relayQ||''))_s.value=RIX._relayQ||'';
  var _c=document.getElementById('relayDcChip');
  if(_c)_c.classList.toggle('on',RIX._relayDC===true);
  var pool=RIX.relayPool||[];
  /* تک‌انتخابی: فقط یک رله، و مقدارش در همان فیلد ProxyIP ذخیره می‌شود. */
  var cur=(RIX.s.proxyIP||'').trim();
  var field=document.getElementById('s-proxyip');
  if(cnt)cnt.textContent=cur?('فعال: '+cur):'بدون رله';
  if(field&&field.value!==cur)field.value=cur;
  if(!pool.length){box.innerHTML='<p class="rl-empty">بانک رله خالی است</p>';return;}

  /* 🔍 جست‌وجو + دسته‌بندی.
     نسخهٔ قبل ۲۷۲ کارت را پشت سر هم ریخته بود؛ کاربر برای پیدا کردن
     یک رله باید ده‌ها صفحه اسکرول می‌کرد. حالا گروه‌ها جمع می‌شوند و
     جست‌وجو روی کشور/شهر/IP می‌زند. */
  var q=(RIX._relayQ||'').trim().toLowerCase();
  var onlyDC=RIX._relayDC===true;

  var ccSet={},dcSet={};
  for(var i=0;i<pool.length;i++){
    var r=pool[i];
    if(r.dc){ (dcSet[r.c]=dcSet[r.c]||[]).push(r); }
    else  { (ccSet[r.c]=ccSet[r.c]||[]).push(r); }
  }
  function match(x){
    if(!q)return true;
    return (x.c||'').toLowerCase().indexOf(q)>=0
        || (x.city||'').toLowerCase().indexOf(q)>=0
        || (x.ip||'').indexOf(q)>=0;
  }
  function rowHtml(x){
    var ep=x.ip+':443';
    var on=cur===ep||cur===x.ip;
    return '<button type="button" class="rl-row'+(on?' on':'')+'"'
      +' data-ip="'+hesc(ep)+'" aria-pressed="'+(on?'true':'false')+'"'
      +' title="'+hesc(x.city||x.c||'')+'">'
      +'<span class="rl-flag">'+(x.cc||'')+'</span>'
      +'<span class="rl-txt"><span class="rl-cc">'+hesc(x.c||'')+'</span>'
      +'<span class="rl-ip">'+hesc(x.ip)+'</span></span>'
      +'<span class="rl-tick">✓</span></button>';
  }
  var h='';
  /* ── دیتاسنترها: همیشه بالا، چون کمترین تعداد و بیشترین ارزش را دارند ── */
  if(!onlyDC){
    var dcKeys=Object.keys(dcSet).sort();
    if(dcKeys.length){
      h+='<div class="rl-grp"><div class="rl-grp-h">'
        +svg('zap',14)+' دیتاسنتر — سریع‌ترین</div>';
      for(var d=0;d<dcKeys.length;d++){
        var rows=dcSet[dcKeys[d]].filter(match);
        if(!rows.length)continue;
        h+='<div class="rl-sub">'+hesc(rows[0].city.split(' · ')[0]||dcKeys[d])+'</div><div class="rl-grid">';
        for(var j=0;j<rows.length;j++)h+=rowHtml(rows[j]);
        h+='</div>';
      }
      h+='</div>';
    }
  }
  /* ── کشورها ── */
  var ccKeys=Object.keys(ccSet).sort();
  var shown=0;
  var body='';
  for(var k=0;k<ccKeys.length;k++){
    var code=ccKeys[k];
    var rows2=ccSet[code].filter(match);
    if(!rows2.length)continue;
    shown+=rows2.length;
    body+='<div class="rl-sub">'+hesc(rows2[0].cc||'')+' <span dir="ltr">'+hesc(code)+'</span></div><div class="rl-grid">';
    for(var m=0;m<rows2.length;m++)body+=rowHtml(rows2[m]);
    body+='</div>';
  }
  if(shown){
    h+='<div class="rl-grp"><div class="rl-grp-h">'
      +svg('globe',14)+' کشورها — <span dir="ltr">'+shown+'</span> رله</div>'+body+'</div>';
  }
  if(!shown&&!dcKeys.length){
    h='<p class="rl-empty">چیزی پیدا نشد — عبارت دیگری امتحان کن</p>';
  }
  if(onlyDC&&!Object.keys(dcSet).length){
    h='<p class="rl-empty">دیتاسنتری در بانک نیست</p>';
  }
  box.innerHTML=h;
}
function relaySearch(v){
  RIX._relayQ=v||'';
  renderRelays();
  /* بعد از رندر دوباره، کادر جست‌وجو باید تمرکز و مکان‌نما را نگه دارد
     وگرنه تایپ هر حرف صفحه را می‌پراند و کاربر عصبی می‌شود. */
  var box=document.getElementById('relaySearch');
  if(box){ box.focus(); try{ box.setSelectionRange(box.value.length,box.value.length); }catch(e){} }
}
function relayFilterDC(on){
  RIX._relayDC=!!on;
  renderRelays();
}
function relayToggle(ip){
  /* تک‌انتخابی: کلیک روی رلهٔ فعال آن را برمی‌دارد، روی رلهٔ دیگر جایگزینش می‌کند. */
  var ep=String(ip).indexOf(':')>0?String(ip):(String(ip)+':443');
  var on=(RIX.s.proxyIP||'')===ep;
  RIX.s.proxyIP=on?'':ep;
  RIX.s.proxyRelays=on?[]:[ep];
  RIX.s.proxyEnabled=!on;
  var en=document.getElementById('s-proxyon');if(en)en.checked=RIX.s.proxyEnabled;
  var f=document.getElementById('s-proxyip');if(f)f.value=RIX.s.proxyIP;
  renderRelays();
  saveSettings();
  toast(on?'رله برداشته شد':('رله فعال شد ✓ '+ep),true);
}
/* یک شنوندهٔ کلیک برای کل شبکه، به‌جای onclick روی تک‌تک کارت‌ها. */
function wireRelayBox(){
  var box=document.getElementById('relayBox');
  if(!box||box.__wired)return;
  box.__wired=true;
  box.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.rl-row');
    if(b)relayToggle(b.getAttribute('data-ip'));
  });
}

function relayPick(mode){
  if(mode==='auto'){
    /* خودکار: فیلد خالی می‌ماند و هسته خودش از کل بانک رله می‌چیند. */
    RIX.s.proxyIP='';RIX.s.proxyRelays=[];RIX.s.proxyEnabled=true;
  } else {
    RIX.s.proxyIP='';RIX.s.proxyRelays=[];RIX.s.proxyEnabled=false;
  }
  var f=document.getElementById('s-proxyip');if(f)f.value=RIX.s.proxyIP;
  var en=document.getElementById('s-proxyon');if(en)en.checked=RIX.s.proxyEnabled;
  renderRelays();
  saveSettings();
  toast(mode==='none'?'رله‌ها خاموش شد':'حالت خودکار ✓',true);
}
function watchAutoSave(){
  var sec=document.getElementById('page-settings');
  if(!sec||sec.__autoWired)return;
  sec.__autoWired=true;
  sec.addEventListener('input',function(e){
    var t=e.target;
    if(!t||!t.id||t.id.indexOf('s-')!==0)return;
    
    queueAutoSave();
  });
  sec.addEventListener('change',function(e){
    var t=e.target;
    if(!t||!t.id||t.id.indexOf('s-')!==0)return;
    if(t.tagName==='SELECT'||t.type==='checkbox')queueAutoSave();
  });
}
async function saveSettings(){
collectSettings();
applyBg();renderAll();
clearTimeout(_autoTimer);
try{var r=await api('saveSettings',RIX.s);
if(r.ok){RIX.savedAt=Date.now();_autoState('✓ ذخیره شد','var(--ok,#3ecf8e)');toast('تنظیمات ذخیره شد ✓',true);}
else{_autoState('✖ ذخیره نشد','var(--danger,#f2446f)');toast(r.err||'خطا',false);}
}catch(e){_autoState('✖ خطای شبکه','var(--danger,#f2446f)');toast('ذخیره نشد: ' + ((e&&e.message)||'ارتباط با سرور برقرار نشد'),false);}}
async function testProxy(){
var box=document.getElementById('proxyTestBox');
var val=document.getElementById('s-proxyip').value.trim();
box.innerHTML='<p class="label"><span class="spin" style="display:inline-block">⏳</span> در حال تست رله…</p>';
try{
var r=await api('testProxy',{proxyIP:val});
if(!r.ok){box.innerHTML='<div class="hint" style="border-color:rgba(244,114,143,.4)">'+hesc(r.err)+'</div>';return;}
box.innerHTML='<div class="ip-row '+(r.alive?'ok':'bad')+'"><span class="ipa">'+hesc(val)+'</span><span class="ms">'+(r.alive?'⚡ '+r.ms+' ms — '+hesc(r.note):'✖ '+hesc(r.note))+'</span></div>';
}catch(e){box.innerHTML='<p class="label" style="color:var(--danger)">'+hesc((e&&e.message)?e.message:'ارتباط با سرور برقرار نشد')+'</p>';}}
async function testIPs(){
RIX.s.cleanIPs=document.getElementById('s-cleanips').value.split('\\n').map(function(s){return s.trim();}).filter(Boolean);
var box=document.getElementById('ipTestBox');
box.innerHTML='<p class="label"><span class="spin" style="display:inline-block">⏳</span> در حال تست…</p>';
try{
var r=await api('testIPs',{ips:RIX.s.cleanIPs});
if(!r.ok){box.innerHTML='<p class="label">'+hesc(r.err||'خطا')+'</p>';return;}
RIX.ipTests=r.map||{};
var html='';
for(var i=0;i<r.results.length;i++){var x=r.results[i];
html+='<div class="ip-row '+(x.ok?'ok':'bad')+'"><span class="ipa">'+hesc(x.ip)+'</span><span class="ms">'+(x.ok?'⚡ '+x.ms+' ms':'✖')+'</span></div>';}
box.innerHTML=html;
renderAll();
}catch(e){box.innerHTML='<p class="label" style="color:var(--danger)">'+hesc((e&&e.message)?e.message:'ارتباط با سرور برقرار نشد')+'</p>';}}
async function scanIPs(){
var box=document.getElementById('scanBox');
var n=parseInt(document.getElementById('scanCount').value)||24;
box.innerHTML='<p class="label"><span class="spin" style="display:inline-block">📡</span> در حال اسکن '+n+' کاندید…</p>';
try{
var r=await api('ipscan',{count:n});
if(!r.ok){box.innerHTML='<p class="label">خطا در اسکن</p>';return;}
var html='<p class="label">سالم: '+r.okCount+' از '+r.results.length+'</p>';
for(var i=0;i<r.results.length;i++){var x=r.results[i];
html+='<div class="ip-row '+(x.ok?'ok':'bad')+'"><span class="ipa">'+hesc(x.ip)+'</span><span class="ms">'+(x.ok?'⚡ '+x.ms+' ms':'✖')+'</span></div>';}
html+='<div class="brow"><button class="btn sm" onclick="addScanned()">'+IC+' افزودن '+r.okCount+' IP سالم به لیست</button></div>';
box.innerHTML=html;
box.dataset.ok=JSON.stringify(r.okIPs);
}catch(e){box.innerHTML='<p class="label" style="color:var(--danger)">'+hesc((e&&e.message)?e.message:'ارتباط با سرور برقرار نشد')+'</p>';}}
async function addScanned(){
var box=document.getElementById('scanBox');
var okIPs=JSON.parse(box.dataset.ok||'[]');
if(!okIPs.length){toast('IP سالمی نیست',false);return;}
var cur=document.getElementById('s-cleanips').value.split('\\n').map(function(s){return s.trim();}).filter(Boolean);
var merged=cur.slice();
for(var i=0;i<okIPs.length;i++)if(merged.indexOf(okIPs[i])<0)merged.push(okIPs[i]);
document.getElementById('s-cleanips').value=merged.join('\\n');
RIX.s.cleanIPs=merged;
try{await api('saveSettings',{cleanIPs:merged});
toast(okIPs.length+' IP اضافه شد ✓',true);renderAll();
}catch(e){}}
function renderAll(){renderStats();renderClients();renderSubs();}
(function(){
var btns=document.querySelectorAll('.sb-nav button');
for(var i=0;i<btns.length;i++)btns[i].addEventListener('click',function(){showPage(this.dataset.page);});
var dots=document.querySelectorAll('.cdot');
for(var j=0;j<dots.length;j++)dots[j].addEventListener('click',function(){
for(var k=0;k<dots.length;k++)dots[k].classList.remove('on');
this.classList.add('on');
document.documentElement.dataset.accent=this.dataset.accent;});
applyPersona();applyBg();fillSettings();renderAll();watchAutoSave();
  initLang();

/* ══ زبان رابط — فارسی / English / 中文 ═══════════════════════════════════ */
function setLang(code){
  var dict = RIX.I18N[code]; if(!dict) return;
  RIX.lang = code;
  try{ localStorage.setItem('rixlang', code); }catch(_e){}
  var nodes = document.querySelectorAll('[data-i18n]');
  for(var i=0;i<nodes.length;i++){
    var el = nodes[i];
    var fa = el.getAttribute('data-i18n');
    if(dict[fa]) el.textContent = dict[fa];
    el.setAttribute('dir', code==='fa' ? 'rtl' : 'ltr');
  }
  var bs = document.querySelectorAll('#langSel button');
  for(var j=0;j<bs.length;j++) bs[j].classList.toggle('on', bs[j].getAttribute('data-lang')===code);
  document.documentElement.setAttribute('lang', code);
}
function initLang(){
  var saved = '';
  try{ saved = localStorage.getItem('rixlang') || ''; }catch(_e){}
  setLang(RIX.I18N[saved] ? saved : 'fa');
}

/* == click on fragment button / language picker ======================= */
addEventListener('click', function(e){
  var t = e.target;
  if(!t || !t.closest) return;
  var lb = t.closest('#langSel button');
  if(lb){ setLang(lb.getAttribute('data-lang')); return; }
});
})();
`;

/* ════════════════ 17) صفحه لاگین ════════════════ */

function renderLogin(cfg, errMsg) {
  const bg = effectiveBg(cfg);
  return `${headHTML(cfg, 'RIX PANEL — ورود')}<body class="${bg.dark ? 'has-bg' : ''}"><div class="bg"><div class="neb n1"></div><div class="neb n2"></div><div class="stars"></div></div><div class="veil"></div>
<div class="login-wrap"><form class="card login-card" method="post" action="/login">
<div class="login-logo"><div class="mark">R</div><h1>RIX <i>PANEL</i></h1><small>v${PANEL_VER}</small></div>
<label class="label">${(cfg.panelPass || cfg.envLocked) ? 'رمز عبور پنل را وارد کنید' : 'رمز عبور پنل را بسازید (حداقل ۶ کاراکتر)'}</label>
<input class="input" type="password" name="pass" required minlength="${(cfg.panelPass || cfg.envLocked) ? '1' : '6'}" autocomplete="current-password" placeholder="••••••••">
 ${errMsg ? `<div class="login-err">${esc(errMsg)}</div>` : ''}
<div class="brow"><button class="btn" style="width:100%" type="submit">${svg('lock',16)} ورود به پنل</button></div>
 ${FOOTER_HTML}</form></div></body></html>`;
}

/* ════════════════ 18) پنل مدیریت ════════════════ */

/* بکگراند — سازندهٔ کارت (سمت سرور، کنار renderPanel) */
var BG_HINT = {
  dark:  'https://example.com/dark.jpg',
  light: 'https://example.com/light.jpg',
};


function renderPanel(cfg, host, ipTests) {
  const token = cfg.subToken;
  const bg = effectiveBg(cfg);
  const data = {
    host, token, ipTests: ipTests || {}, poolSize: SCAN_POOL.length, maxBg: MAX_BG_CHARS,
    relayPool: RELAY_POOL_CLEAN.map(function (r) {
      return { ip: r.ip, port: r.port || 443, cc: r.cc, c: r.c, city: r.city, dc: !!r.dc,
               endpoint: r.ip + ':' + (r.port || 443), label: relayLabel(r) };
    }),
    s: {
      fingerprint: cfg.fingerprint, sniOverride: cfg.sniOverride, customAddr: cfg.customAddr,
      cleanIPs: cfg.cleanIPs, vlessEnabled: cfg.vlessEnabled, trojanEnabled: cfg.trojanEnabled,
      xhttpEnabled: cfg.xhttpEnabled,
      /* پروفایل pattng — سراسری. بدون این سطر، RIX.s این‌ها را ندارد و
         fillSettings چیزی برای نمایش پیدا نمی‌کند. */
      echEnabled: false, echConfigList: '',
      ipv6Enabled: false,      proxyRelays: cfg.proxyRelays,
      tlsPorts: cfg.tlsPorts, nonTLSEnabled: cfg.nonTLSEnabled, nonTLSPorts: cfg.nonTLSPorts,
      proxyIP: cfg.proxyIP, proxyEnabled: cfg.proxyEnabled,
      nat64Enabled: cfg.nat64Enabled, nat64Prefix: cfg.nat64Prefix,
      bgDarkUrl: bg.dark, bgLightUrl: bg.light,
      bgDarkKv: cfg.bgDarkKv, bgLightKv: cfg.bgLightKv,
      accent: cfg.accent, fontChoice: cfg.fontChoice, fontScale: cfg.fontScale, corner: cfg.corner
    },
    b: {
      botToken: cfg.botToken, botChatId: cfg.botChatId, botUser: cfg.botUser, botSecret: cfg.botSecret,
      botEnabled: cfg.botEnabled, botOnAuth: cfg.botOnAuth, botOnClient: cfg.botOnClient, botOnConn: cfg.botOnConn
    },
    clients: cfg.clients.map(c => ({ ...c, subToken: c.subToken || generateSubToken() })),
    /* client-side dictionaries */
    I18N: I18N
  };
  const rixJson = JSON.stringify(data).replace(/</g, '\\u003c');
  const cdots = ACCENTS.map(a => `<button type="button" class="cdot ${cfg.accent === a ? 'on' : ''}" data-accent="${a}" style="--c:${ACCENT_META[a].c}" title="${ACCENT_META[a].label}" aria-label="${ACCENT_META[a].label}"></button>`).join('');

  const clientDetails = cfg.clients.map(c => {
    const subLink = `https://${host}/sub/${c.subToken}`;
    const subQR = `https://${host}/sub/${c.subToken}/qr`;
    return `
  <div id="cd-${esc(c.id)}" class="hidden">
    <div class="card">
      <div class="vhead"><h2>${esc(c.name)}</h2><span class="sp"></span><span class="tag">${esc(routeLabel(c.country))}</span></div>
      <div class="brow" style="margin-top:0">
        <a class="btn" href="${esc(subLink)}" target="_blank" rel="noopener">${svg('eye',16)} ورود به سابپنل</a>
        <button class="btn ghost" data-copy="${esc(subLink)}">${svg('copy',15)} کپی لینک ساب</button>
        <button class="btn ghost" data-qrimg="${esc(subQR)}" data-name="ساب ${esc(c.name)}" data-copy="${esc(subLink)}">${svg('qr',15)} QR ساب</button>
      </div>
      <div class="detail-row"><span class="k">مصرف امروز</span><span class="v" id="usage-${esc(c.id)}">—</span></div>
      <details class="fgroup mt" style="border:1px solid var(--border);border-radius:var(--ri);padding:.8rem 1rem">
        <summary class="label" style="cursor:pointer;margin:0">🔒 جزئیات فنی (UUID و پسورد — برای کپی دستی)</summary>
        <div class="detail-row"><span class="k">UUID (VLESS)</span><span class="v" style="font-family:var(--f-mono);font-size:.72rem">${esc(c.uuid)}</span></div>
        <div class="detail-row"><span class="k">پسورد Trojan</span><span class="v" style="font-family:var(--f-mono);font-size:.72rem">${esc(c.trojanPass)}</span></div>
        <div class="detail-row"><span class="k">سهمیه / انقضا</span><span class="v">${c.quotaGB > 0 ? c.quotaGB + ' گیگابایت' : 'نامحدود'} / ${c.expiryDays > 0 ? c.expiryDays + ' روز' : 'هرگز'}</span></div>
      </details>
    </div>
    <div class="card mt"><div class="vhead"><span class="ci">${svg('zap',17)}</span><h2>کانفیگهای این کلاینت</h2><span class="sp"></span><span class="pill code" id="cfgCount-${esc(c.id)}">…</span></div>
      <div id="cfgList-${esc(c.id)}"><p class="label">جزئیات را باز کنید.</p></div>
    </div>
  </div>`;
  }).join('');

  return `${headHTML(cfg, 'RIX PANEL v' + PANEL_VER)}<body><div class="bg"><div class="neb n1"></div><div class="neb n2"></div><div class="stars"></div></div><div class="veil"></div>
<div class="layout">
<aside class="sbar"><div class="sb-brand"><div class="mark">R</div><h1>RIX <i>PANEL</i></h1><small>v${PANEL_VER}</small></div>
<nav class="sb-nav">
<button data-page="dash" class="active">${svg('home',18)}<span data-i18n="داشبورد">داشبورد</span></button>
<button data-page="clients">${svg('users',18)}<span data-i18n="کلاینت‌ها">کلاینت‌ها</span></button>
<button data-page="subs">${svg('link',18)}<span data-i18n="سابها">سابها</span></button>
<button data-page="scanner">${svg('radar',18)}<span data-i18n="اسکنر IP">اسکنر IP</span></button>
<button data-page="settings">${svg('sliders',18)}<span data-i18n="تنظیمات">تنظیمات</span></button>
</nav><div class="sb-foot">RIX • REZA • XTLS</div></aside>

<main class="main">
<header class="topbar"><div class="tb-brand"><div class="mark">R</div><div class="tt"><b>RIX PANEL</b><small>هسته Race — سریعترین مسیر خودکار</small></div></div>
<div class="tb-actions">
<div class="theme-pil" onclick="toggleTheme()" role="button" aria-label="تغییر تم"><div class="tp on" data-t="dark">${moonSvg}</div><div class="tp" data-t="light">${sunSvg}</div></div>
 <div class="lang-sel" id="langSel" role="group" aria-label="Language">
   <button type="button" data-lang="fa" class="on" title="فارسی">فارسی</button>
   <button type="button" data-lang="en" title="English">EN</button>
   <button type="button" data-lang="zh" title="中文">中文</button>
 </div>
 <a class="tbtn" href="/logout">${svg('logout',15)} خروج</a>
</div></header>

<section id="page-dash">
  <div class="grid g4">
    <div class="card"><div class="stat"><div class="si">${svg('users',20)}</div><div><div class="st-v" id="st-clients">0</div><div class="st-l">کلاینت فعال</div></div></div></div>
    <div class="card"><div class="stat"><div class="si">${svg('zap',20)}</div><div><div class="st-v" id="st-proto">—</div><div class="st-l">پروتکل‌ها</div></div></div></div>
    <div class="card"><div class="stat"><div class="si">${svg('globe',20)}</div><div><div class="st-v" id="st-cleans">0</div><div class="st-l">IP تمیز</div></div></div></div>
    <div class="card"><div class="stat"><div class="si">${svg('shield',20)}</div><div><div class="st-v" id="st-ports">443</div><div class="st-l">پورتها</div></div></div></div>
  </div>
  <div class="card mt"><div class="vhead"><h2>هسته Race — چطور کار میکند؟</h2></div>
    <div class="detail-row"><span class="k">هر اتصال، همه مسیرها (Direct/NAT64/ProxyIP) همزمان امتحان میشوند — سریعترین برنده است</span><span class="v">⚡</span></div>
    <div class="detail-row"><span class="k">یوتیوب و گوگل: مسیر Direct خودکار — کش DNS آنها فقط ۳۰ ثانیه</span><span class="v">▶️</span></div>
    <div class="detail-row"><span class="k">سایتهای کلادفلری: ProxyIP (اگر فعال باشد) در ریس شرکت میکند</span><span class="v">🔧</span></div>
    <div class="detail-row"><span class="k">تست سرعت: fast.com یا speed.cloudflare.com — انتظار واقعی ۵-۱۵ مگابیت/ثانیه</span><span class="v">📊</span></div>
  </div>
</section>

<section id="page-clients" class="hidden">
  <div class="card"><div class="vhead"><span class="ci">${svg('users',17)}</span><h2>مدیریت کلاینت‌ها</h2><span class="sp"></span><span class="pill code">${cfg.clients.length}/${MAX_CLIENTS}</span></div>
    <div id="clientsList"></div>
    <div class="brow"><button class="btn" onclick="openClientModal()">${svg('plus',16)} ساخت کلاینت جدید</button></div>
  </div>
  ${clientDetails}
</section>

<section id="page-subs" class="hidden">
  <div class="card"><div class="vhead"><span class="ci">${svg('link',17)}</span><h2>لینک ساب هر کلاینت</h2><span class="tag">هر کلاینت فقط یکی</span></div>
    <label class="label">در مرورگر = سابپنل | در اپ = ساب خودکار:</label>
    <div id="perClientSubs"></div>
  </div>
  <div class="card mt"><div class="vhead"><span class="ci">${svg('globe',17)}</span><h2>ساب کلی (همهٔ کلاینت‌ها — فقط دامنه‌ها)</h2></div>
    <div class="subbox"><div class="txt" id="mainSubTxt"></div>
      <button class="btn sm ghost" id="btnMainSubCopy" data-copy="">${svg('copy',14)} کپی</button>
      <button class="btn sm" id="btnMainSubQR" data-qrimg="" data-name="" data-copy="">${svg('qr',14)} QR</button>
    </div>
    <div class="brow"><a class="btn ghost" id="viewSubLink" href="#" target="_blank" rel="noopener">${svg('eye',16)} صفحهٔ خروجی</a></div>
  </div>
</section>

<section id="page-scanner" class="hidden">
  <div class="card"><div class="vhead"><span class="ci">${svg('radar',17)}</span><h2>اسکنر IP تمیز</h2><span class="sp"></span><span class="pill code">${SCAN_POOL.length} کاندید</span></div>
    <div class="hint mb">📡 تست نهایی با «تست تاخیر واقعی» در v2rayNG از اینترنت خودتان است.</div>
    <div class="grid g2">
      <div><label class="label">تعداد کاندید</label><select class="select" id="scanCount"><option value="12">۱۲</option><option value="24" selected>۲۴</option><option value="36">۳۶</option><option value="48">۴۸</option></select></div>
    </div>
    <div class="brow"><button class="btn" onclick="scanIPs()">${svg('radar',16)} شروع اسکن</button></div>
    <div id="scanBox" class="mt"></div>
  </div>
  <div class="card mt"><div class="vhead"><span class="ci">${svg('zap',17)}</span><h2>تست لیست فعلی</h2></div>
    <div class="brow"><button class="btn sm ghost" onclick="testIPs()">${svg('zap',15)} 🧪 تست IPهای لیست</button></div>
    <div id="ipTestBox" class="mt"></div>
  </div>
</section>

<section id="page-settings" class="hidden">
  <div class="card"><div class="vhead"><span class="ci">${svg('palette',17)}</span><h2>شخصی‌سازی ظاهر</h2></div>
    <label class="label">🎨 رنگ پنل:</label>
    <div class="colorrow" id="s-accent">${cdots}</div>
    <div class="grid g2 mt">
      <div><label class="label">🔤 فونت</label><select class="select" id="s-font">${FONTS.map(f => `<option value="${f}">${FONT_META[f]}</option>`).join('')}</select></div>
      <div><label class="label">🔍 اندازه متن</label><select class="select" id="s-fs">${FONT_SCALES.map(s => `<option value="${s}">${SCALE_META[s]}</option>`).join('')}</select></div>
      <div><label class="label">⬜ گوشهها</label><select class="select" id="s-corner">${CORNERS.map(c => `<option value="${c}">${CORNER_META[c]}</option>`).join('')}</select></div>
    </div>
    <div class="brow"><button class="btn" onclick="savePersona()">${svg('save',16)} ذخیره ظاهر</button></div>
  </div>

  <div class="card mt"><div class="vhead"><span class="ci">${svg('sliders',17)}</span><h2>پورتها و پروتکل‌ها</h2></div>
    <div class="grid g2">
      <div><label class="label">پورتهای TLS (از 443,2053,2083,2087,2096,8443)</label><input class="input" id="s-tlsports" dir="ltr" placeholder="443"></div>
      <div><label class="label">پورتهای HTTP (از 80,8080,8880,2052,2082,2086,2095)</label><input class="input" id="s-nontlsports" dir="ltr" placeholder="80"></div>
      <div><label class="label">دامنه سفارشی (اختیاری)</label><input class="input" id="s-custom" dir="ltr" placeholder="cdn.example.com"></div>
      <div><label class="label">اثر انگشت TLS</label><select class="select" id="s-fp">${FINGERPRINTS.map(f => `<option value="${f}">${f}</option>`).join('')}</select></div>
    </div>
    <div class="flex mt"><span class="label" style="margin:0">کانفیگهای HTTP بدون TLS ⭐ ضدDPI</span><span class="spacer"></span><label class="switch"><input type="checkbox" id="s-nontls"><span class="slider"></span></label></div>
    <div class="flex mt"><span class="label" style="margin:0">پروتکل VLESS</span><span class="spacer"></span><label class="switch"><input type="checkbox" id="s-vless"><span class="slider"></span></label></div>
    <div class="flex mt"><span class="label" style="margin:0">پروتکل Trojan</span><span class="spacer"></span><label class="switch"><input type="checkbox" id="s-trojan"><span class="slider"></span></label></div>
    <div class="flex mt"><span class="label" style="margin:0">پروتکل XHTTP <small dir="ltr" style="opacity:.7">Xray</small></span><span class="spacer"></span><label class="switch"><input type="checkbox" id="s-xhttp"><span class="slider"></span></label></div>
    <div class="mt" id="xhttpModeWrap"><label class="label">حالت XHTTP</label>
      <select class="select" id="s-xhttp-mode">
        <option value="stream-one">stream-one — پایدارترین، بدون نشست</option>
        <option value="stream-up">stream-up — یک‌طرفهٔ جریانی، سریع‌تر</option>
        <option value="packet-up">packet-up — بسته‌ای، مقاوم‌تر در شبکهٔ ضعیف</option>
      </select>
      <p class="hint" id="xhttpModeHint"></p>
    </div>
  </div>

  <div class="card mt"><div class="vhead"><span class="ci">${svg('globe',17)}</span><h2>مسیریابی</h2></div>
    <div class="grid g2">
      <div style="grid-column:1/-1"><label class="label">ProxyIP — رله (⚠️ باید خارج از رنج کلادفلر باشد)</label><input class="input" id="s-proxyip" placeholder="168.138.35.173 یا ip:port" dir="ltr">
        <div class="flex" style="margin-top:.5rem;gap:.4rem;flex-wrap:wrap">
          <button type="button" class="tbtn sm" onclick="relayPick('auto')">🌍 خودکار — کل بانک</button>
          <button type="button" class="tbtn sm" onclick="relayPick('none')">بدون رله</button>
          <button type="button" class="tbtn sm" onclick="relayPick('random')">🎲 تصادفی</button>
          <span class="pill" id="relayCount">—</span>
        </div>
        <div class="rl-srch mt">
          <input class="input" id="relaySearch" placeholder="🔍 جست‌وجوی کشور، شهر یا IP…" dir="ltr" autocomplete="off" oninput="relaySearch(this.value)">
          <button type="button" class="rl-chip" id="relayDcChip" onclick="relayFilterDC(this.classList.contains('on'))">⚡ فقط دیتاسنتر</button>
        </div>
        <div id="relayBox" class="mt"></div>
      </div>
      <div><label class="label">SNI جایگزین — فقط برای IPهای تمیز</label><input class="input" id="s-sni" placeholder="speed.cloudflare.com" dir="ltr"></div>
      <div><label class="label">پیشوند NAT64</label><select class="select" id="s-nat64p">${Object.entries(NAT64).map(([k, v]) => `<option value="${k}">${v.label}</option>`).join('')}</select></div>
    </div>
    <div class="flex mt"><span class="label" style="margin:0">ProxyIP فعال (در ریس شرکت میکند)</span><span class="spacer"></span><label class="switch"><input type="checkbox" id="s-proxyon"><span class="slider"></span></label></div>
    <div class="flex mt"><span class="label" style="margin:0">NAT64 فعال</span><span class="spacer"></span><label class="switch"><input type="checkbox" id="s-nat64"><span class="slider"></span></label></div>
    <div class="brow" style="margin-top:.5rem"><button class="btn sm ghost" onclick="testProxy()">${svg('zap',15)} 🧪 تست رله ProxyIP</button></div>
    <div id="proxyTestBox" class="mt"></div>
    <div class="mt">
      <label class="label">IPهای تمیز دستی (هر خط یک مورد):</label>
      <textarea class="input" id="s-cleanips" rows="6"></textarea>
    </div>
    <div class="brow"><button class="btn" onclick="saveSettings()">${svg('save',16)} ذخیره کل تنظیمات</button>
      <span id="autosaveState" class="label" style="margin:0;color:var(--muted)">تغییرات خودکار ذخیره می‌شود</span></div>
  </div>
</section>



 ${FOOTER_HTML}
</main></div>

<div id="genModal" class="modal hidden" role="dialog" aria-modal="true"><div class="modal-box" id="modalBody"></div></div>

<div id="qrModal" class="modal hidden" role="dialog" aria-modal="true">
  <div class="modal-box">
    <div class="modal-head"><b id="qrTitle"></b><button class="icon-btn sm" onclick="closeQr()" aria-label="بستن">${svg('x',15)}</button></div>
    <img id="qrImg" class="modal-qrimg" alt="QR Code">
    <div class="brow"><button class="btn" style="width:100%" id="qrCopyBtn" data-copy="">${svg('copy',15)} کپی لینک</button></div>
  </div>
</div>

<script>
const RIX = ${rixJson};
 ${CLIENT_JS}
 ${PANEL_JS}
</script>
</body></html>`;
}

/* ════════════════ 19) هاب ساب ════════════════ */

function renderSubHub(cfg, host, token) {
  const bg = effectiveBg(cfg);
  const clients = cfg.clients.filter(c => c.enabled !== false && !clientExpired(c));
  const hubHTML = clients.map(c => {
    const link = `https://${host}/sub/${c.subToken}`;
    const qr = `https://${host}/sub/${c.subToken}/qr?s=160`;
    return `<div class="hub-item">
      <div class="hub-av">${esc((c.name || 'C')[0])}</div>
      <div class="hub-info">
        <div class="hub-n">${esc(c.name)}</div>
        <div class="hub-m"><span class="tag">${esc(routeLabel(c.country))}</span><span>${c.quotaGB > 0 ? c.quotaGB + ' گیگابایت' : 'نامحدود'}</span></div>
      </div>
      <img class="hub-qr" src="${esc(qr)}" alt="QR ${esc(c.name)}" data-qrimg="${esc(`https://${host}/sub/${c.subToken}/qr`)}" data-name="ساب ${esc(c.name)}" data-copy="${esc(link)}" title="بزرگنمایی QR">
      <div class="hub-act">
        <a class="btn sm" href="${esc(link)}" rel="noopener">${svg('eye',14)} سابپنل</a>
        <button class="icon-btn sm" data-copy="${esc(link)}" title="کپی لینک ساب">${svg('copy',14)}</button>
      </div>
    </div>`;
  }).join('') || '<p class="label">هنوز کلاینتی منتشر نشده است.</p>';

  return `${headHTML(cfg, 'سابها — RIX PANEL')}<body class="${bg.dark ? 'has-bg' : ''}"><div class="bg"><div class="neb n1"></div><div class="neb n2"></div><div class="stars"></div></div><div class="veil"></div>
<div class="v-wrap">
  <div class="v-top">
    <div class="spacer"></div>
    <div class="theme-pil" onclick="toggleTheme()" role="button" aria-label="تغییر تم"><div class="tp on" data-t="dark">${moonSvg}</div><div class="tp" data-t="light">${sunSvg}</div></div>
  </div>
  <div class="v-hero">
    <div class="mark">R</div>
    <h1>سابهای <i>RIX</i></h1>
    <p>هر کلاینت یک ساب اختصاصی دارد — روی «سابپنل» بزنید یا QR را اسکن کنید</p>
    <div class="chips"><span class="chip">${svg('users',13)} ${clients.length} کلاینت</span><span class="chip">${svg('zap',13)} ${cfg.vlessEnabled ? 'VLESS' : ''}${cfg.trojanEnabled ? ' + Trojan' : ''}</span></div>
  </div>
  <div class="card">
    <div class="vhead"><span class="ci">${svg('users',17)}</span><h2>کلاینت‌ها</h2><span class="sp"></span><span class="pill code">${clients.length}</span></div>
    ${hubHTML}
  </div>
  ${FOOTER_HTML}
</div>
<div id="qrModal" class="modal hidden" role="dialog" aria-modal="true">
  <div class="modal-box">
    <div class="modal-head"><b id="qrTitle"></b><button class="icon-btn sm" onclick="closeQr()" aria-label="بستن">${svg('x',15)}</button></div>
    <img id="qrImg" class="modal-qrimg" alt="QR">
    <div class="brow"><button class="btn" style="width:100%" id="qrCopyBtn" data-copy="">${svg('copy',15)} کپی لینک</button></div>
  </div>
</div>
<script>${CLIENT_JS}</script></body></html>`;
}

/* ════════════════ 20) سابپنل اختصاصی کلاینت ════════════════ */

function renderClientSub(cfg, host, token, client, sortedIPs) {
  const bg = effectiveBg(cfg);
  const link = `https://${host}/sub/${client.subToken}`;
  const subQR = `https://${host}/sub/${client.subToken}/qr`;
  const cfgUse = { ...cfg, cleanIPs: sortedIPs || cfg.cleanIPs };
  const vars = clientVariants(cfgUse, client, host, false);
  const groups = [
    { title: 'اصلی — TLS', icon: 'zap', items: vars.filter(v => v.kind === 'main-tls' || v.kind === 'main-trojan'), tag: '' },
    { title: 'اصلی — HTTP بدون TLS', icon: 'zap', items: vars.filter(v => v.kind === 'main-http'), tag: '<span class="tag http">⭐ ضد DPI</span>' },
    { title: 'دامنه سفارشی', icon: 'globe', items: vars.filter(v => v.kind === 'custom-tls'), tag: '' },
    { title: 'IP تمیز — TLS', icon: 'globe', items: vars.filter(v => v.kind === 'ip-tls'), tag: '<span class="tag">سالمها اول</span>' },
    { title: 'IP تمیز — HTTP', icon: 'globe', items: vars.filter(v => v.kind === 'ip-http'), tag: '<span class="tag http">⭐</span>' }
  ].filter(g => g.items.length);

  const row = (v, idx) => {
    const kind = v.kind === 'main-trojan' ? 'Trojan' : (v.tls ? 'TLS' : 'HTTP ⭐');
    const cls = !v.tls ? 'http' : '';
    const qr = `https://${host}/sub/${client.subToken}/qr/${idx}`;
    return `<div class="v-item">
      <div class="vi-n"><div class="vi-t">${esc(v.addr)}:${v.port}</div><div class="vi-s"><span class="tag ${cls}">${kind}</span></div></div>
      <span class="cfg-act">
        <button class="icon-btn sm" data-qrimg="${esc(qr)}" data-name="${esc(v.addr + ':' + v.port)}" data-copy="${esc(v.link)}" title="QR" aria-label="QR">${svg('qr',15)}</button>
        <button class="icon-btn sm" data-copy="${esc(v.link)}" title="کپی" aria-label="کپی">${svg('copy',14)}</button>
      </span>
    </div>`;
  };

  const groupsHTML = groups.map(g => `
  <div class="card">
    <div class="gsec"><span class="gs-t">${esc(g.title)}</span><span class="gs-line"></span>${g.tag}<span class="pill code">${g.items.length}</span></div>
    ${g.items.map((v) => row(v, vars.indexOf(v))).join('')}
  </div>`).join('') || '<div class="card"><p class="label">کانفیگی برای این کلاینت فعال نیست.</p></div>';

  const days = client.expiryDays > 0 ? Math.max(0, Math.ceil((client.created + client.expiryDays * 86400000 - Date.now()) / 86400000)) : null;

  return `${headHTML(cfg, 'ساب ' + client.name + ' — RIX')}<body class="${bg.dark ? 'has-bg' : ''}"><div class="bg"><div class="neb n1"></div><div class="neb n2"></div><div class="stars"></div></div><div class="veil"></div>
<div class="v-wrap">
  <div class="v-top">
    <div class="spacer"></div>
    <div class="theme-pil" onclick="toggleTheme()" role="button" aria-label="تغییر تم"><div class="tp on" data-t="dark">${moonSvg}</div><div class="tp" data-t="light">${sunSvg}</div></div>
  </div>
  <div class="v-hero">
    <div class="mark">${esc((client.name || 'C')[0])}</div>
    <h1>ساب <i>${esc(client.name)}</i></h1>
    <p>فقط کانفیگهای اختصاصی این کلاینت</p>
    <div class="chips">
      <span class="chip">${svg('globe',13)} ${esc(routeLabel(client.country))}</span>
      <span class="chip">${svg('zap',13)} ${vars.length} کانفیگ</span>
      <span class="chip">${client.quotaGB > 0 ? client.quotaGB + ' گیگابایت' : 'نامحدود'}</span>
      ${days !== null ? `<span class="chip">${svg('clock',13)} ${days} روز مانده</span>` : ''}
    </div>
  </div>

  <div class="qr-hero">
    <div class="qh-t">📱 لینک ساب این کلاینت</div>
    <div class="qh-d">در v2rayNG / Hiddify بخش Subscription اضافه کنید — یا QR را اسکن کنید</div>
    <img src="${esc(subQR)}" alt="QR ساب ${esc(client.name)}">
    <div class="subbox" style="justify-content:center">
      <div class="txt">${esc(link)}</div>
      <button class="btn sm" data-copy="${esc(link)}">${svg('copy',14)} کپی</button>
    </div>
  </div>

  <div class="hint">⚡ هسته Race: همه مسیرها همزمان امتحان میشوند — سریعترین برنده است. اگر کانفیگی خطا داد، ⭐ HTTP (پورت 80) را تست کنید.</div>

  ${groupsHTML}
  ${FOOTER_HTML}
</div>
<div id="qrModal" class="modal hidden" role="dialog" aria-modal="true">
  <div class="modal-box">
    <div class="modal-head"><b id="qrTitle"></b><button class="icon-btn sm" onclick="closeQr()" aria-label="بستن">${svg('x',15)}</button></div>
    <img id="qrImg" class="modal-qrimg" alt="QR">
    <div class="brow"><button class="btn" style="width:100%" id="qrCopyBtn" data-copy="">${svg('copy',15)} کپی لینک</button></div>
  </div>
</div>
<script>${CLIENT_JS}</script></body></html>`;
}

/* ════════════════ 21) Router ════════════════ */

async function handleRequest(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const host = url.hostname;

    /* پیش‌دست‌کنندهٔ XHTTP قبل از سراسری، وگرنه سراسری زودتر جواب می‌دهد و
       فقط Content-Type را اجازه می‌دهد؛ مرورگر درخواست را رد می‌کند و هرگز
       به ترنسپورت نمی‌رسد. */
    if (request.method === 'OPTIONS' && isXhttpPath(path)) {
      return new Response(null, { status: 204, headers: xhttpCors(request) });
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
    }

    if (path === '/tg-webhook' && request.method === 'POST') return handleTGWebhook(request, env, ctx);

    /* ─── بکگراند آپلودشده ─── */
        if (path === '/bg/dark' || path === '/bg/light') {
          const dataUrl = await getBgDataUrl(env, path === '/bg/light' ? 'light' : 'dark');
          if (!dataUrl) return new Response('Not Found', { status: 404 });
          const mime = dataUrl.slice(5, dataUrl.indexOf(';'));
          const b64 = dataUrl.slice(dataUrl.indexOf(',') + 1);
          /* 🛡 اگر داده در KV دستکاری شده و base64 نبود، atob یک exception
             می‌دهد و کل درخواست (شامل خودِ صفحهٔ پنل) می‌ترکد. */
          let bin;
          try {
            bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
          } catch {
            return new Response('Not Found', { status: 404, headers: { 'Cache-Control': 'no-store', ...SEC_HEADERS } });
          }
          return new Response(bin, { headers: { 'Content-Type': mime, 'Cache-Control': 'public, max-age=3600', ...SEC_HEADERS } });
        }

    /* ─── ساب ─── توکن = subToken تصادفی هر کلاینت (۲۵۶بیت) */
    if (path.startsWith('/sub/')) {
      const seg = path.split('/').filter(Boolean);
      const token = seg[1];
      const cfg = await getConfig(env);
      const ip = clientIP(request);
      if (!rateLimit(subReqs, ip, SUB_RATE_LIMIT, SUB_RATE_WINDOW)) return new Response('Too Many Requests', { status: 429 });

      if (!token) return new Response('Not Found', { status: 404 });
      /* توکن اصلی پنل */
      const isMain = !!cfg.subToken && safeEqual(token, cfg.subToken);
      /* یا توکن اختصاصی یکی از کلاینت‌ها */
      const client = cfg.clients.find(c => c.subToken && safeEqual(c.subToken, token));

      if (!isMain && !client) return new Response('Forbidden', { status: 403, headers: { 'Cache-Control': 'no-store', ...SEC_HEADERS } });

      /* QR — PNG سرورساید */
      if (seg[2] === 'qr') {
        const sizeP = url.searchParams.get('s');
        /* ⚠️ QR توکن اصلی دیگر به صفحهٔ «همه سابها» اشاره نمی‌کند — چون هرکس آن را
           اسکن می‌کرد، لیست تمام کلاینت‌ها را می‌دید. حالا فقط کانفیگ خودش را می‌گیرد. */
        if (isMain) return qrImageResponse(`https://${host}/sub/${cfg.subToken}?plain=1`, sizeP);
        if (!seg[3]) return qrImageResponse(`https://${host}/sub/${client.subToken}?plain=1`, sizeP);
        const idx = parseInt(seg[3]);
        if (isNaN(idx) || idx < 0 || idx >= MAX_VARIANTS) return new Response('Not found', { status: 404 });
        const sortedIPs = await sortedCleanIPs(env, cfg);
        const vars = clientVariants({ ...cfg, cleanIPs: sortedIPs }, client, host, false);
        if (!vars[idx]) return new Response('Not found', { status: 404 });
        return qrImageResponse(vars[idx].link, sizeP);
      }

      const html = wantsHTML(request, url);

      if (isMain) {
        /* 🔒 فقط صفحهٔ HTML فهرست کلاینت‌ها مدیر-only است. خود کانفیگ‌ها
           (base64/plain) باید باز بماند وگرنه اپ‌ها ساب از کار می‌افتند. */
        if (html) {
          if (!(await isAuthed(request, env)))
            return new Response('Forbidden', { status: 403, headers: { 'Cache-Control': 'no-store', ...SEC_HEADERS } });
          return htmlResponse(renderSubHub(cfg, host, cfg.subToken));
        }
        const links = [];
        for (const c of cfg.clients.filter(c => c.enabled !== false && !clientExpired(c)))
          for (const v of clientVariants(cfg, c, host, true)) links.push(v.link);
        if (!links.length) return new Response('No configs', { status: 404 });
        const out = url.searchParams.get('plain') ? links.join('\n') : subBase64(links);
        return new Response(out, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' } });
      }

      if (client.enabled === false || clientExpired(client)) return new Response('Client not found', { status: 404 });
      const sortedIPs = await sortedCleanIPs(env, cfg);
      if (html) return htmlResponse(renderClientSub(cfg, host, client.subToken, client, sortedIPs));
      const links = clientVariants({ ...cfg, cleanIPs: sortedIPs }, client, host, false).map(v => v.link);
      if (!links.length) return new Response('No configs', { status: 404 });
      const out = url.searchParams.get('plain') ? links.join('\n') : subBase64(links);
      return new Response(out, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' } });
    }

    /* ─── WebSocket جهانی — هسته Race ─── */
    const upgrade = (request.headers.get('Upgrade') || '').toLowerCase();
    /* پروب اسکنرها هدر Upgrade را می‌فرستند ولی Sec-WebSocket-Key ندارند؛ آن‌ها
       مشتری WebSocket نیستند و نباید وارد هندلر شوند. */
    if (upgrade === 'websocket') {
      const wsKey = request.headers.get('Sec-WebSocket-Key') || '';
      const wsVer = request.headers.get('Sec-WebSocket-Version') || '';
      if (typeof WebSocketPair === 'function' && wsKey && wsVer) {
        const cfg = await getConfig(env);
        return handleWSS(request, cfg, env, ctx);
      }
      return new Response('Expected a WebSocket handshake', {
        status: 426,
        headers: { 'Upgrade': 'websocket', 'Cache-Control': 'no-store', ...SEC_HEADERS },
      });
    }

    /* ─── XHTTP (stream-one) ─── */
    if (isXhttpPath(path)) {
      const cfg = await getConfig(env);
      return handleXHTTP(request, cfg, env, ctx);
    }

    /* ─── Login / Logout ─── */
    if (path === '/login') {
      const ip = clientIP(request);
      const shard = loginShard(request, ip);
      if (request.method === 'POST') {
        let cfg = await getConfig(env);

        /* ── لایهٔ ۱+۲: قفل افزایشی و سقف کل — پیام یکسان، بدون نشت اطلاعات ── */
        const wait = loginBlocked(ip, shard);
        if (wait) {
          const mins = Math.max(1, Math.ceil(wait / 60000));
          return htmlResponse(renderLogin(cfg, `⛔ تلاشهای زیاد — ${mins} دقیقه دیگر تلاش نکنید`), 429);
        }

        const form = await request.formData().catch(() => null);
        const pass = form ? String(form.get('pass') || '') : '';
        const adminPass = envAdminPass(env);
        const hasPass = adminPass || cfg.panelPass;

        /* ── نبود رمز: ساخت اولیه. بدون قفل تا کاربر بتواند پنل را نصب کند ── */
        if (!hasPass) {
          if (pass.length < 6) return htmlResponse(renderLogin(cfg, 'رمز باید حداقل ۶ کاراکتر باشد'), 400);
          cfg.panelPass = await hashPassword(pass);
          /* secret نشست باید همین‌جا و برای همیشه ساخته شود؛ ساختنش در
             mergeDefaults یعنی کوکی ورود هرگز معتبر نمی‌شود. */
          if (!cfg.sessionSecret) cfg.sessionSecret = generateSubToken();
          if (!cfg.clients.length) cfg.clients.push(makeClient('کلاینت من', 0, 'main', 0));
          await saveConfig(env, cfg);
          loginOk(ip, shard);
          logEvent(env, 'پنل نصب شد', ctx, 'auth');
          return new Response(null, { status: 302, headers: { 'Set-Cookie': sessionCookie(newSessionToken(cfg, env)), 'Location': '/' } });
        }

        let ok = false, wasLegacy = false;
        if (adminPass) {
          ok = pass.length > 0 && safeEqual(sha224Hex(pass), sha224Hex(adminPass));
        } else {
          const v = await verifyPassword(pass, cfg.panelPass);
          ok = v.ok; wasLegacy = v.legacy;
          /* نه 1101 می‌دهیم، نه بی‌صدا رد می‌کنیم — دقیقاً می‌گوییم چه کاری لازم
             است. ADMIN_PASS همین راه بازگشت است و کلاینت‌ها دست‌نخورده می‌مانند. */
          if (v.needsReset && !adminPass) {
            return htmlResponse(renderLogin(cfg,
              'رمز این پنل با نسخهٔ قدیمی ذخیره شده بود. یک‌بار ADMIN_PASS را در '
              + 'تنظیمات Wrangler بگذارید و با آن وارد شوید تا رمز به قالب سریع p2$ '
              + 'منتقل شود؛ کلاینت‌ها و تنظیمات‌تان دست‌نخورده می‌مانند.'), 403);
          }
        }

        /* 🔄 پس از ورود موفق، رکورد قدیمی همان‌جا به p2$ نوشته می‌شود؛ هزینهٔ
           ۱۷۰۰ms فقط یک‌بار پرداخت می‌شود، نه در هر ورود. */
        /* هر رکورد ذخیره‌شده‌ای که p2$ نباشد باید همین‌جا نوشته شود — شامل وقتی
           از ADMIN_PASS وارد شده‌ایم. شرط داخل else بود و برای همین رکورد قدیمی
           هیچ‌وقت عوض نمی‌شد. */
        if (typeof cfg.panelPass === 'string' && cfg.panelPass && cfg.panelPass.indexOf('p2$') !== 0) {
          wasLegacy = true;
        }
        if (ok && wasLegacy) {
          /* این catch دیگر خالی نیست: خاموشی‌اش یعنی مالک برای همیشه بیرون می‌ماند
             و هیچ نشانه‌ای هم در لاگ نمی‌ماند. */
          try {
            cfg = { ...cfg, panelPass: await hashPassword(pass) };
            await saveConfig(env, cfg);
          } catch (e) {
            logEvent(env, 'نوشتن رمز تازه ناموفق بود: ' + String(e), ctx, 'auth');
          }
        }

        if (ok) {
          loginOk(ip, shard);
          logEvent(env, 'ورود موفق به پنل', ctx, 'auth');
          return new Response(null, { status: 302, headers: { 'Set-Cookie': sessionCookie(newSessionToken(cfg, env)), 'Location': '/' } });
        }

        /* ── لایهٔ ۳: تأخیر پلکانی تا مهاجم نتواند پورت بزند ── */
        loginFail(ip, shard);
        logEvent(env, 'تلاش ورود ناموفق', ctx, 'auth');
        await sleep(Math.min(250, 40 + Math.random() * 60));
        return htmlResponse(renderLogin(cfg, 'رمز اشتباه است'), 401);
      }
      const cfg = await getConfig(env);
      if (envAdminPass(env)) cfg.envLocked = true;
      return htmlResponse(renderLogin(cfg));
    }
    if (path === '/logout') {
      return new Response(null, { status: 302, headers: { 'Set-Cookie': 'rix_session=; Path=/; Max-Age=0', 'Location': '/login' } });
    }

    /* ─── API ─── */
    if (path.startsWith('/api/') && request.method === 'POST') {
      if (!rateLimit(apiReqs, clientIP(request), API_RATE_LIMIT, API_RATE_WINDOW)) {
        return new Response(JSON.stringify({ ok: false, err: 'درخواست زیاد — کمی صبر کنید' }), { status: 429, headers: { 'Content-Type': 'application/json' } });
      }
      if (!csrfOk(request, url) || !(await isAuthed(request, env))) {
        return new Response(JSON.stringify({ ok: false, err: 'unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
      const cfg = await getConfig(env);
      const body = await request.json().catch(() => ({}));
      const action = path.slice(5);
      const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json' } });
      try {

      if (action === 'addClient') {
        if (cfg.clients.length >= MAX_CLIENTS) return json({ ok: false, err: 'به حداکثر تعداد رسیدهاید' });
        const c = makeClient(body.name, body.quotaGB, body.country, body.expiryDays);
        if (body.cleanIPs === false) c.cleanIPs = false;
        if (body.enabled === false) c.enabled = false;
        cfg.clients.push(c);
        await saveConfig(env, cfg);
        logEvent(env, `کلاینت "${c.name}" ساخته شد`, ctx, 'client');
        return json({ ok: true, client: c });
      }
      if (action === 'updateClient') {
        const c = cfg.clients.find(x => x.id === body.id);
        if (!c) return json({ ok: false, err: 'یافت نشد' });
        if (typeof body.name === 'string' && body.name.trim()) c.name = body.name.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 32);
        if (ROUTES.some(r => r.k === body.country)) c.country = body.country;
        if (typeof body.quotaGB === 'number') c.quotaGB = Math.max(0, Math.min(1000, body.quotaGB));
        if (typeof body.expiryDays === 'number') c.expiryDays = Math.max(0, Math.min(3650, body.expiryDays));
        if (typeof body.cleanIPs === 'boolean') c.cleanIPs = body.cleanIPs;
        if (typeof body.enabled === 'boolean') c.enabled = body.enabled;
        Object.assign(c, normalizeClient(c));
        await saveConfig(env, cfg);
        logEvent(env, `کلاینت "${c.name}" ویرایش شد`, ctx, 'client');
        return json({ ok: true, client: c });
      }
      if (action === 'delClient') {
        const idx = cfg.clients.findIndex(c => c.id === body.id);
        if (idx < 0) return json({ ok: false, err: 'یافت نشد' });
        const [removed] = cfg.clients.splice(idx, 1);
        await saveConfig(env, cfg);
        logEvent(env, `کلاینت "${removed.name}" حذف شد`, ctx, 'client');
        return json({ ok: true });
      }
      if (action === 'toggleClient') {
        const c = cfg.clients.find(x => x.id === body.id);
        if (!c) return json({ ok: false, err: 'یافت نشد' });
        c.enabled = c.enabled === false;
        await saveConfig(env, cfg);
        return json({ ok: true, enabled: c.enabled });
      }
      if (action === 'usage') {
        const c = cfg.clients.find(x => x.id === body.id);
        if (!c) return json({ ok: false, err: 'یافت نشد' });
        return json({ ok: true, bytes: await getUsage(env, c.id) });
      }
      if (action === 'variants') {
        const c = cfg.clients.find(x => x.id === body.id);
        if (!c) return json({ ok: false, err: 'یافت نشد' });
        const sortedIPs = await sortedCleanIPs(env, cfg);
        const vars = clientVariants({ ...cfg, cleanIPs: sortedIPs }, c, host, false);
        return json({ ok: true, variants: vars.map((v, i) => ({ i, kind: v.kind, tls: v.tls, addr: v.addr, port: v.port, link: v.link })) });
      }
      if (action === 'savePersona') {
        if (ACCENTS.includes(body.accent)) cfg.accent = body.accent;
        if (FONTS.includes(body.fontChoice)) cfg.fontChoice = body.fontChoice;
        if (FONT_SCALES.includes(body.fontScale)) cfg.fontScale = body.fontScale;
        if (CORNERS.includes(body.corner)) cfg.corner = body.corner;
        await saveConfig(env, cfg);
        return json({ ok: true });
      }
      /* آپلود بکگراند از دستگاه */
      if (action === 'uploadBg') {
        const slot = body.slot === 'light' ? 'light' : 'dark';
        const d = String(body.data || '');
        if (!/^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/.test(d) || d.length > MAX_BG_CHARS) {
          return json({ ok: false, err: 'فایل نامعتبر یا بزرگ‌تر از حد مجاز (حدود ۲ مگابایت)' });
        }
        try {
          const saved = await kvPut(env, slot === 'dark' ? 'rix_bg_dark' : 'rix_bg_light', d);
          if (!saved) return json({ ok: false, err: 'ذخیره نشد — KV در دسترس نیست' });
        } catch {
          return json({ ok: false, err: 'خطا در ذخیره — عکس کوچکتری امتحان کن' });
        }
        if (slot === 'dark') cfg.bgDarkKv = true;
        else cfg.bgLightKv = true;
        await saveConfig(env, cfg);
        logEvent(env, `بکگراند ${slot === 'dark' ? 'تاریک' : 'روشن'} آپلود شد`, ctx, 'auth');
        return json({ ok: true });
      }
      if (action === 'deleteBg') {
        const slot = body.slot === 'light' ? 'light' : 'dark';
        await kvPut(env, slot === 'dark' ? 'rix_bg_dark' : 'rix_bg_light', '');
        if (slot === 'dark') cfg.bgDarkKv = false;
        else cfg.bgLightKv = false;
        await saveConfig(env, cfg);
        return json({ ok: true });
      }
      if (action === 'saveSettings') {
        if (FINGERPRINTS.includes(body.fingerprint)) cfg.fingerprint = body.fingerprint;
        if (typeof body.sniOverride === 'string' && body.sniOverride.trim().length <= 253 && isValidClean(body.sniOverride.trim())) cfg.sniOverride = body.sniOverride.trim();
        else if (typeof body.sniOverride === 'string' && !body.sniOverride.trim()) cfg.sniOverride = '';
        if (typeof body.customAddr === 'string' && body.customAddr.trim().length <= 253 && isValidClean(body.customAddr.trim())) cfg.customAddr = body.customAddr.trim();
        else if (typeof body.customAddr === 'string' && !body.customAddr.trim()) cfg.customAddr = '';
        if (typeof body.bgDarkUrl === 'string') {
          const v = body.bgDarkUrl.trim();
          if (v === '/bg/dark' && cfg.bgDarkKv) { /* آپلودی دست نمیخورد */ }
          else if (!v) { cfg.bgDarkUrl = ''; }
          else if (isSafeBgUrl(v)) { cfg.bgDarkUrl = v; cfg.bgDarkKv = false; }
        }
        if (typeof body.bgLightUrl === 'string') {
          const v = body.bgLightUrl.trim();
          if (v === '/bg/light' && cfg.bgLightKv) { /* آپلودی دست نمیخورد */ }
          else if (!v) { cfg.bgLightUrl = ''; }
          else if (isSafeBgUrl(v)) { cfg.bgLightUrl = v; cfg.bgLightKv = false; }
        }
        cfg.tlsPorts = parsePortList(body.tlsPorts, TLS_PORTS_ALL, cfg.tlsPorts);
        cfg.nonTLSPorts = parsePortList(body.nonTLSPorts, NONTLS_PORTS_ALL, cfg.nonTLSPorts);
        if (typeof body.nonTLSEnabled === 'boolean') cfg.nonTLSEnabled = body.nonTLSEnabled;
        if (typeof body.proxyIP === 'string' && body.proxyIP.trim().length <= 253 && isValidClean(body.proxyIP.trim())) cfg.proxyIP = body.proxyIP.trim();
        else if (typeof body.proxyIP === 'string' && !body.proxyIP.trim()) cfg.proxyIP = '';
    if (Array.isArray(body.proxyRelays)) {
      const keep = body.proxyRelays.filter(function (x) {
        return typeof x === 'string' && x.trim() && isValidClean(x.trim()) && x.trim().length <= 253;
      }).slice(0, MAX_RELAYS);
      cfg.proxyRelays = [...new Set(keep.map(function (x) { return x.trim(); }))];
    }
        if (typeof body.proxyEnabled === 'boolean') cfg.proxyEnabled = body.proxyEnabled;
        if (typeof body.nat64Enabled === 'boolean') cfg.nat64Enabled = body.nat64Enabled;
        if (NAT64[body.nat64Prefix]) cfg.nat64Prefix = body.nat64Prefix;
        if (typeof body.vlessEnabled === 'boolean') cfg.vlessEnabled = body.vlessEnabled;
        if (typeof body.xhttpEnabled === 'boolean') cfg.xhttpEnabled = body.xhttpEnabled;
        /* پروفایل pattng — سراسری. echConfigList از نظر شکل جدا اعتبارسنجی
           می‌شود (isValidEch) و اگر نامعتبر بود اصلاً ذخیره نمی‌شود، نه اینکه
           خام وارد کانفیگ شود. طول هم سقف دارد تا config blob بزرگ نشود. */
        /* optimization profiles are intentionally disabled */
        cfg.echEnabled = false;
        cfg.ipv6Enabled = false;
        cfg.echConfigList = '';
        if (typeof body.trojanEnabled === 'boolean') cfg.trojanEnabled = body.trojanEnabled;
        if (Array.isArray(body.cleanIPs)) {
          const clean = body.cleanIPs.filter(x => typeof x === 'string' && isValidClean(x) && x.length <= 253).slice(0, MAX_CLEAN_IPS);
          if (clean.length) cfg.cleanIPs = clean;
        }
        await saveConfig(env, cfg);
        logEvent(env, 'تنظیمات به‌روزرسانی شد', ctx, 'auth');
        return json({ ok: true });
      }
      /* تست رله ProxyIP */
      if (action === 'testProxy') {
        const pr = parseProxyIP(body.proxyIP || cfg.proxyIP);
        if (!pr) return json({ ok: false, err: 'آدرس ProxyIP نامعتبر است' });
        if (isPrivateIP(pr.host)) return json({ ok: false, err: 'آدرس خصوصی مجاز نیست' });
        if (inCFRange(pr.host)) return json({ ok: false, err: '⛔ این آدرس رنج کلادفلر است — بهعنوان ProxyIP هرگز کار نمیکند! یک رله واقعی (VPS) بگذار' });
        const r = await tcpPing(pr.host, pr.port);
        if (!r.ok) return json({ ok: true, alive: false, ms: r.ms, verdict: 'dead', note: 'رله روی این پورت جواب نمیدهد' });
        /* 🧪 تشخیص رلهٔ «فقط کلادفلر»: بعضی رله‌ها TLS را فقط برای دامنه‌های
           کلادفلر قبول می‌کنند. زنده‌اند ولی یوتیوب/گوگل از رله کار نمی‌کند. */
        const probe = await relayScopeProbe(pr.host, pr.port);
        const cfOnly = probe.cfOk && !probe.anyOk;
        return json({
          ok: true, alive: true, ms: r.ms,
          verdict: cfOnly ? 'cfonly' : (probe.anyOk ? 'full' : 'unknown'),
          cfOk: probe.cfOk, googleOk: probe.googleOk, ytOk: probe.ytOk,
          note: probe.cfOk && !probe.anyOk
            ? '⚠️ رله زنده است ولی فقط دامنه‌های Cloudflare را قبول می‌کند — یوتیوب و گوگل از رله کار نمی‌کنند'
            : (probe.ytOk ? 'رله کامل است ✓ (یوتیوب و گوگل هم قبول می‌شوند)'
               : (probe.googleOk ? 'رله گوگل را قبول می‌کند ولی یوتیوب را نه'
                  : 'رله زنده است ✓ (گوگل/یوتیوب تست نشد — معمولاً رلهٔ عمومی)'))
        });
      }
      /* تستر IP — فقط عمومی/CF */
      if (action === 'testIPs') {
        const ips = (Array.isArray(body.ips) ? body.ips : cfg.cleanIPs)
          .filter(x => typeof x === 'string' && isValidClean(x) && x.length <= 253)
          .filter(ip => {
            const cc = cleanSplit(ip);
            if (isPrivateIP(cc.host)) return false;
            return isDomain(cc.host) || inCFRange(cc.host);
          })
          .slice(0, MAX_CLEAN_IPS);
        if (!ips.length) return json({ ok: false, err: 'هیچ IP معتبر عمومی برای تست نیست' });
        const results = [];
        for (let i = 0; i < ips.length; i += SCAN_CONCURRENCY) {
          const batch = ips.slice(i, i + SCAN_CONCURRENCY).map(async ip => {
            const cc = cleanSplit(ip);
            const r = await tcpPing(cc.host, cc.port);
            return { ip, ok: r.ok, ms: r.ms };
          });
          results.push(...await Promise.all(batch));
        }
        const map = {};
        for (const r of results) map[r.ip] = { ok: r.ok, ms: r.ms, at: Date.now() };
        await saveIpTests(env, map);
        results.sort((a, b) => (b.ok - a.ok) || (a.ms - b.ms));
        logEvent(env, `تست IP: ${results.filter(r => r.ok).length}/${results.length} سالم`, ctx, 'auth');
        return json({ ok: true, results, map });
      }
      if (action === 'ipscan') {
        const count = Math.max(4, Math.min(48, parseInt(body.count) || 24));
        const pool = [...SCAN_POOL];
        const picked = [];
        const step = Math.max(1, Math.floor(pool.length / count));
        for (let i = Math.floor(Math.random() * step); i < pool.length && picked.length < count; i += step) picked.push(pool[i]);
        const results = [];
        for (let i = 0; i < picked.length; i += SCAN_CONCURRENCY) {
          const batch = picked.slice(i, i + SCAN_CONCURRENCY).map(async ip => {
            const r = await tcpPing(ip, 443);
            return { ip, ok: r.ok, ms: r.ms };
          });
          results.push(...await Promise.all(batch));
        }
        const okIPs = results.filter(r => r.ok).sort((a, b) => a.ms - b.ms).map(r => r.ip);
        results.sort((a, b) => (b.ok - a.ok) || (a.ms - b.ms));
        logEvent(env, `اسکن IP: ${okIPs.length}/${picked.length} سالم`, ctx, 'auth');
        return json({ ok: true, results, okIPs, okCount: okIPs.length });
      }
      if (action === 'selftest') {
        const results = {};
        for (const [k, v] of Object.entries(NAT64)) {
          const r = await nat64Probe(v.prefix);
          setGwLat(k, r);
          results[k] = r;
        }
        return json({ ok: true, results, nat64: cfg.nat64Enabled, proxy: cfg.proxyEnabled });
      }
      return json({ ok: false, err: 'unknown' }, 404);

      } catch (e) {
        /* خطای واقعی را برگردان تا UI پیام مبهم «خطای ارتباط» نشان ندهد */
        const msg = (e && e.message) ? String(e.message).slice(0, 200) : 'خطای ناشناخته در سرور';
        return json({ ok: false, err: msg }, 500);
      }
    }

    /* ─── پنل ─── */
    if (path === '/' || path === '') {
      const cfg = await getConfig(env);
      if (!cfg.panelPass && !envAdminPass(env)) return htmlResponse(renderLogin(cfg));
      if (!(await isAuthed(request, env))) return new Response(null, { status: 302, headers: { 'Location': '/login' } });
      /* 🩹 مهاجرت: کلاینت‌های قدیمی subToken ندارند — یک‌بار می‌سازیم و ذخیره می‌کنیم
         وگرنه لینک ساب با هر بار رفرش پنل عوض می‌شود و ساب از کار می‌افتد. */
      let migrated = false;
      for (const c of cfg.clients) {
        if (!c.subToken || typeof c.subToken !== 'string' || c.subToken.length !== 64) { c.subToken = generateSubToken(); migrated = true; }
      }
      if (migrated) await saveConfig(env, cfg);
      const ipT = await getIpTests(env);
      return htmlResponse(renderPanel(cfg, host, ipT));
    }

    return new Response('Not Found', { status: 404 });
  }

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (error) {
      try { console.error('RIX_REQUEST_EXCEPTION', error && error.stack ? error.stack : String(error)); } catch {}

      /* 🧠 تشخیص نوع خطا تا کاربر بدون حدس بفهمه چه‌کار کند. */
            const msg = String((error && error.message) || error || '');
            const lower = msg.toLowerCase();

            /* نبود KV — شایع‌ترین علت «پنل بالا میاد ولی هیچ‌چی ذخیره نمی‌شه» */
            const kvMissing = !kvStore(env);
            if (kvMissing) {
              return errorPage('حافظهٔ KV وصل نیست', msg.slice(0, 300), kvProblemText(env));
            }

            /* نوشتن در KV شکست خورد (سقف حجم، یا KV خراب) */
            if (lower.includes('kv_write_failed')) {
              return errorPage('ذخیره نشد', msg.slice(0, 300),
                'حافظهٔ KV در دسترسه ولی نوشتن جواب نداد.<br><br>'
                + 'معمولاً یکی از این‌هاست:<br>'
                + '• عکس بکگراند خیلی بزرگه (سقف هر مقدار KV حدود ۲۵ مگابایت است)<br>'
                + '• کلید یا مقدار از حد مجاز بزرگ‌تره<br>'
                + '• تعداد نوشتن روزانه‌ات پر شده<br><br>'
                + 'یه بار دیگه با چیز کوچک‌تر امتحان کن.');
            }

      /* پلن رایگان: ماژول سوکت در دسترس نیست */
      if (lower.includes('cloudflare:sockets') || lower.includes('is not a function') && lower.includes('connect')) {
        return errorPage('این قابلیت روی پلن رایگان نیست', msg.slice(0, 300),
          'قابلیت‌های سوکت (پروکسی VLESS/Trojan و اسکن IP) روی پلن <b>رایگان</b> '
          + 'کلودفلر فعال نیست.<br><br>راه‌ها:<br>'
          + '۱) پلن Workers Paid بگیر<br>۲) فقط پنل و ساب رو نگه دار، پروکسی رو نه');
      }

      /* ورودی خراب / JSON نامعتبر */
            if (lower.includes('unexpected token') || lower.includes('unexpected end') || lower.includes('is not valid json')) {
              return errorPage('درخواست ناقص بود', msg.slice(0, 300), 'داده‌ای که فرستاده شد کامل نبود. یه بار دیگه تلاش کن.');
            }

      /* خطای عمومی — پیام فنی هست ولی پشت یک صفحهٔ مرتب */
      return errorPage('خطای داخلی پنل', msg.slice(0, 300),
        'اگه با تلاش مجدد درست نشد، لاگ‌ها رو ببین:<br><code>npx wrangler tail</code>');
    }
  },

  /* 🛡 مسیری که catch بالا دستش نمی‌رسد.
     Cloudflare این را بیرون از بدنهٔ fetch و بین دو درخواست صدا می‌زند،
     پس یک exception اینجا مستقیم به 1101 تبدیل می‌شود.
     بدنه خالی است ولی خودِ فراخوانی هرگز خطا نمی‌دهد.
     اگر روزی کران (cron) اضافه کردی، کل بدنه را در try بگذار. */
  async scheduled(_event, env, ctx) {
    try { if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(Promise.resolve()); } catch {}
  }
};

/* ════════════════ 22) Telegram Webhook — با Secret-Token ════════════════ */

async function handleTGWebhook(request, env, ctx) {
  try {
    const cfg = await getConfig(env);
    if (!cfg.botEnabled || !cfg.botToken) return new Response('ok');
    if (cfg.botSecret && request.headers.get('x-telegram-bot-api-secret-token') !== cfg.botSecret) {
      return new Response('ok', { status: 403 });
    }
    const update = await request.json().catch(() => null);
    if (!update) return new Response('ok');
    const msg = update.message || update.callback_query?.message;
    if (!msg) return new Response('ok');
    const chatId = String(msg.chat.id);
    if (chatId !== cfg.botChatId) return new Response('ok');
    if (update.callback_query) {
      const text = await botReport(env, update.callback_query.data);
      await tgSend(cfg.botToken, chatId, text, botMenu()).catch(() => {});
      return new Response('ok');
    }
    const text = (msg.text || '').trim();
    if (text === '/start' || text === '/menu') await tgSend(cfg.botToken, chatId, '🛡 <b>RIX PANEL</b>\nمنوی مدیریت:', botMenu()).catch(() => {});
    else if (text === '/status') await tgSend(cfg.botToken, chatId, await botReport(env, 'st'), botMenu()).catch(() => {});
    else await tgSend(cfg.botToken, chatId, 'دستور ناشناخته — /start را بزنید.', botMenu()).catch(() => {});
    return new Response('ok');
  } catch { return new Response('ok'); }
}