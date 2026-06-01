"""
SAMdu Loyiha — SQLite ma'lumotlar bazasi v2.0
Yangilandi: audit_log, login_attempts, csrf_tokens, media jadvallar
"""
import sqlite3, os, hashlib, json, secrets, string
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "samdu.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # ── USERS ──────────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        password_salt TEXT DEFAULT '',
        full_name TEXT,
        role TEXT DEFAULT 'student',
        faculty TEXT,
        course INTEGER DEFAULT 1,
        specialty TEXT,
        hemis_id TEXT,
        rating INTEGER DEFAULT 0,
        achievements INTEGER DEFAULT 0,
        avatar TEXT DEFAULT '',
        email TEXT DEFAULT '',
        phone TEXT DEFAULT '',
        active INTEGER DEFAULT 1,
        last_login TEXT DEFAULT '',
        login_count INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── ATHLETES ───────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS athletes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        full_name TEXT NOT NULL,
        sport TEXT,
        faculty TEXT,
        course INTEGER,
        level TEXT DEFAULT 'university',
        achievements TEXT DEFAULT '[]',
        medals_gold INTEGER DEFAULT 0,
        medals_silver INTEGER DEFAULT 0,
        medals_bronze INTEGER DEFAULT 0,
        rating_points INTEGER DEFAULT 0,
        coach TEXT,
        bio TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── MENTORS ────────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS mentors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        full_name TEXT NOT NULL,
        subjects TEXT DEFAULT '[]',
        rating REAL DEFAULT 0.0,
        sessions_total INTEGER DEFAULT 0,
        students_total INTEGER DEFAULT 0,
        experience_years INTEGER DEFAULT 0,
        bio TEXT DEFAULT '',
        price_per_hour INTEGER DEFAULT 0,
        available INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── TALENTS ────────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS talents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        full_name TEXT NOT NULL,
        faculty TEXT,
        specialty TEXT,
        course INTEGER,
        categories TEXT DEFAULT '[]',
        score INTEGER DEFAULT 0,
        achievements TEXT DEFAULT '[]',
        portfolio TEXT DEFAULT '[]',
        bio TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── HACKATHONS ─────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS hackathons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'upcoming',
        prize TEXT,
        deadline TEXT,
        participants INTEGER DEFAULT 0,
        max_participants INTEGER DEFAULT 0,
        tech_stack TEXT DEFAULT '',
        organizer TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── EVENTS ─────────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        location TEXT,
        event_date TEXT,
        event_time TEXT,
        category TEXT DEFAULT 'general',
        capacity INTEGER DEFAULT 0,
        registered INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── NOTIFICATIONS ──────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        body TEXT,
        notif_type TEXT DEFAULT 'info',
        read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── SESSIONS (mentoring) ───────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mentor_id INTEGER REFERENCES mentors(id) ON DELETE CASCADE,
        student_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        subject TEXT,
        status TEXT DEFAULT 'pending',
        session_date TEXT,
        session_time TEXT,
        duration_min INTEGER DEFAULT 60,
        notes TEXT DEFAULT '',
        admin_note TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── SETTINGS ───────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT DEFAULT (datetime('now'))
    )""")

    # ══ YANGI JADVALLAR ════════════════════════════════════════

    # ── AUDIT LOG ──────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT DEFAULT '',
        action TEXT NOT NULL,
        target_type TEXT DEFAULT '',
        target_id INTEGER DEFAULT 0,
        details TEXT DEFAULT '',
        ip_address TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── LOGIN ATTEMPTS ─────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip_address TEXT DEFAULT '',
        success INTEGER DEFAULT 0,
        user_agent TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── CSRF TOKENS ────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS csrf_tokens (
        token TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL
    )""")

    # ── MEDIA (fayl yuklash) ───────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        file_type TEXT DEFAULT 'image',
        file_size INTEGER DEFAULT 0,
        uploaded_by INTEGER REFERENCES users(id),
        entity_type TEXT DEFAULT '',
        entity_id INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── RATE LIMITS ────────────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        request_count INTEGER DEFAULT 1,
        window_start TEXT DEFAULT (datetime('now')),
        blocked_until TEXT DEFAULT ''
    )""")

    # ── SITE ANNOUNCEMENTS ─────────────────────────────────────
    c.execute("""CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT,
        type TEXT DEFAULT 'info',
        active INTEGER DEFAULT 1,
        pinned INTEGER DEFAULT 0,
        created_by INTEGER REFERENCES users(id),
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT DEFAULT ''
    )""")

    # ── INDEXES ────────────────────────────────────────────────
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_login_ip      ON login_attempts(ip_address)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_login_user    ON login_attempts(username)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_rate_ip       ON rate_limits(ip_address)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_notif_user    ON notifications(user_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ment ON sessions(mentor_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_stud ON sessions(student_id)")

    conn.commit()

    # ── MIGRATE existing tables (safe: ADD COLUMN if missing) ──
    _migrate(conn)

    _seed_data(conn)
    conn.close()


def _migrate(conn):
    """Mavjud ustunlarni tekshirib, yo'q bo'lsa qo'shadi (safe migration)"""
    c = conn.cursor()

    def _col_exists(table, col):
        cols = [r[1] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]
        return col in cols

    def _tbl_exists(table):
        r = c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        return r is not None

    migrations = {
        "users":      [("password_salt","TEXT DEFAULT ''"),
                       ("email","TEXT DEFAULT ''"),
                       ("phone","TEXT DEFAULT ''"),
                       ("last_login","TEXT DEFAULT ''"),
                       ("login_count","INTEGER DEFAULT 0")],
        "athletes":   [("bio","TEXT DEFAULT ''")],
        "talents":    [("bio","TEXT DEFAULT ''")],
        "hackathons": [("max_participants","INTEGER DEFAULT 0"),
                       ("tech_stack","TEXT DEFAULT ''"),
                       ("organizer","TEXT DEFAULT ''")],
        "events":     [("capacity","INTEGER DEFAULT 0"),
                       ("registered","INTEGER DEFAULT 0")],
        "sessions":   [("duration_min","INTEGER DEFAULT 60"),
                       ("notes","TEXT DEFAULT ''"),
                       ("admin_note","TEXT DEFAULT ''")],
        "notifications": [("notif_type","TEXT DEFAULT 'info'")],
        "settings":   [("updated_at","TEXT DEFAULT (datetime('now'))")],
    }

    for table, cols in migrations.items():
        if not _tbl_exists(table):
            continue
        for col, col_def in cols:
            if not _col_exists(table, col):
                try:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
                    conn.commit()
                except Exception:
                    pass

    # Yangi jadvallar migration
    new_tables = ["audit_log", "login_attempts", "csrf_tokens", "media",
                  "rate_limits", "announcements"]
    for t in new_tables:
        if not _tbl_exists(t):
            # init_db() already creates them, but just in case
            pass


def _hash_password(password: str, salt: str = "") -> str:
    """Salted SHA-256 hash"""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256(f"{salt}{password}{salt[::-1]}".encode()).hexdigest()
    return hashed, salt


def verify_password(password: str, stored_hash: str, salt: str = "") -> bool:
    """Parolni tekshirish"""
    if salt:
        computed, _ = _hash_password(password, salt)
        return computed == stored_hash
    # Backwards compat: eski usulsiz hash
    return hashlib.sha256(password.encode()).hexdigest() == stored_hash


def _hash(pw: str) -> str:
    """Backwards-compat: eski plain SHA-256"""
    return hashlib.sha256(pw.encode()).hexdigest()


def _seed_data(conn):
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username='200519992806'")
    if c.fetchone():
        return  # already seeded

    # ── ADMIN ─────────────────────────────────────────────────
    # Login: 200519992806  |  Parol: 200519992806
    admin_hash, admin_salt = _hash_password("200519992806")
    c.execute("""INSERT INTO users(username,password,password_salt,full_name,role,email)
                 VALUES(?,?,?,?,?,?)""",
              ("200519992806", admin_hash, admin_salt,
               "Bosh Administrator", "admin", "admin@tatu.uz"))

    # ── TALABA (asosiy) ────────────────────────────────────────
    # Login: 1200519992806  |  Parol: 1200519992806
    st_hash, st_salt = _hash_password("1200519992806")
    c.execute("""INSERT INTO users(username,password,password_salt,full_name,role,
                 faculty,course,specialty,rating,achievements)
                 VALUES(?,?,?,?,?,?,?,?,?,?)""",
              ("1200519992806", st_hash, st_salt,
               "Asosiy Talaba", "student", "KTIF", 3, "Dasturlash", 847, 12))

    # ── QO'SHIMCHA DEMO FOYDALANUVCHILAR ──────────────────────
    s2h, s2s = _hash_password("1234")
    s3h, s3s = _hash_password("1234")
    c.execute("""INSERT INTO users(username,password,password_salt,full_name,role,
                 faculty,course,specialty,rating,achievements)
                 VALUES(?,?,?,?,?,?,?,?,?,?)""",
              ("student2", s2h, s2s,
               "Zulfiya Tosheva", "student", "EIQ", 2, "AI/ML", 792, 9))
    c.execute("""INSERT INTO users(username,password,password_salt,full_name,role,
                 faculty,course,specialty,rating,achievements)
                 VALUES(?,?,?,?,?,?,?,?,?,?)""",
              ("student3", s3h, s3s,
               "Bobur Nazarov", "student", "MMF", 1, "Matematika", 620, 5))

    # Athletes
    for fn, sp, fac, crs, lvl, mg, ms, mb, rp in [
        ("Jasur Umarov",  "Futbol",    "KTIF", 3, "republic",      45, 10, 8, 320),
        ("Nilufar Rahimova","Kurash",  "EIQ",  2, "international", 30, 12, 9, 410),
        ("Bobur Mirzayev","Basketbol", "MMF",  4, "region",        20,  5, 3, 180),
        ("Dilnoza Xasanova","Voleybol","KTIF", 1, "university",    10,  2, 1,  90),
        ("Sardor Ismoilov","Shaxmat",  "ITF",  3, "republic",      60,  8, 5, 280),
        ("Feruza Nazarova","Tennis",   "EIQ",  2, "region",        15,  3, 2, 120),
    ]:
        c.execute("""INSERT INTO athletes(full_name,sport,faculty,course,level,
                     medals_gold,medals_silver,medals_bronze,rating_points) VALUES(?,?,?,?,?,?,?,?,?)""",
                  (fn, sp, fac, crs, lvl, mg, ms, mb, rp))

    # Mentors
    for fn, subj, rat, st, stt, exp, bio in [
        ("Kamol Tursunov",  '["Python","ML","Data Science"]',  4.9, 124, 87, 8, "10+ yil tajriba"),
        ("Sarvar Qodirov",  '["JavaScript","React","Node.js"]', 4.8, 98,  64, 6, "Full-stack developer"),
        ("Malika Ergasheva", '["UI/UX","Figma","Adobe XD"]',   4.7, 76,  52, 5, "Product designer"),
        ("Nodir Kalandarov",'["C++","Algorithms","DSA"]',       4.6, 89,  70, 7, "Competitive programmer"),
    ]:
        c.execute("""INSERT INTO mentors(full_name,subjects,rating,sessions_total,
                     students_total,experience_years,bio) VALUES(?,?,?,?,?,?,?)""",
                  (fn, subj, rat, st, stt, exp, bio))

    # Talents
    for fn, fac, spec, crs, cats, sc in [
        ("Ali Karimov",    "KTIF","Dasturlash",  3,'["science","creative"]', 920),
        ("Zulfiya Tosheva","EIQ", "AI/ML",       2,'["science"]',            875),
        ("Jasur Umarov",   "KTIF","Dasturlash",  3,'["sport"]',              830),
        ("Nilufar Rahimova","EIQ","Moliya",       2,'["sport","social"]',     810),
        ("Sardor Ismoilov","ITF", "Kiberjurnalistika",3,'["science","sport"]', 790),
        ("Oybek Normatov", "MMF","Matematika",   4,'["science"]',            760),
        ("Dilnoza Xasanova","KTIF","Dasturlash", 1,'["sport","creative"]',   720),
        ("Kamola Mirzayeva","HF", "Pedagogika",  2,'["social","creative"]',  695),
    ]:
        c.execute("""INSERT INTO talents(full_name,faculty,specialty,course,categories,score)
                     VALUES(?,?,?,?,?,?)""", (fn, fac, spec, crs, cats, sc))

    # Hackathons
    for tit, desc, stat, prize, dl, part in [
        ("TATU Hackathon 2025","Aqlli shahar yechimlarini yaratish","open",
         "10,000,000 so'm","2025-08-15", 48),
        ("AI Challenge","Sun'iy intellekt loyihalari musobaqasi","upcoming",
         "5,000,000 so'm","2025-09-01", 0),
        ("Web Dev Cup","Zamonaviy veb-ilovalar yaratish","closed",
         "3,000,000 so'm","2025-05-01", 32),
    ]:
        c.execute("""INSERT INTO hackathons(title,description,status,prize,deadline,participants)
                     VALUES(?,?,?,?,?,?)""", (tit, desc, stat, prize, dl, part))

    # Events
    for tit, desc, loc, dt, tm, cat in [
        ("TATU Sport Festivali","Yillik sport festivali","Sport kompleksi","2025-07-20","10:00","sport"),
        ("Hackathon 2025","Dasturlash musobaqasi","A blok, 3-qavat","2025-08-15","09:00","it"),
        ("Ilmiy konferensiya","Talabalar ilmiy ishlari","Konferensiya zali","2025-07-25","09:00","science"),
        ("Mentor Training","Mentorlik dasturi ta'lim","B blok","2025-07-18","14:00","education"),
    ]:
        c.execute("""INSERT INTO events(title,description,location,event_date,event_time,category)
                     VALUES(?,?,?,?,?,?)""", (tit, desc, loc, dt, tm, cat))

    # Settings
    for k, v in [
        ("site_name",        "S_TATU Platform"),
        ("university",       "Samarqand TATU"),
        ("total_students",   "8420"),
        ("total_athletes",   "312"),
        ("total_mentors",    "48"),
        ("total_talents",    "156"),
        ("registration_open","1"),
        ("maintenance",      "0"),
        ("maintenance_msg",  "Tizim texnik ishlar olib bormoqda. Tez orada qaytamiz."),
        ("allowed_admin_ips",""),
        ("max_login_attempts","5"),
        ("lockout_minutes",  "30"),
        ("session_lifetime", "480"),
        ("contact_email",    "admin@tatu.uz"),
        ("contact_phone",    "+998662390000"),
    ]:
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))

    # Announcement
    c.execute("""INSERT INTO announcements(title,body,type,active,pinned,created_by)
                 VALUES(?,?,?,?,?,?)""",
              ("Xush kelibsiz!", "S_TATU platforma yangilandi. Barcha talabalar ro'yxatdan o'tishingiz mumkin.", "success", 1, 1, 1))

    # Audit log: seed
    c.execute("""INSERT INTO audit_log(user_id,username,action,details)
                 VALUES(?,?,?,?)""", (1, "admin", "system_init", "Ma'lumotlar bazasi yaratildi"))

    conn.commit()
