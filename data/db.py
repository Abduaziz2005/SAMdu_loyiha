"""
SAMdu Loyiha — SQLite ma'lumotlar bazasi
"""
import sqlite3, os, hashlib, json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "samdu.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    # ── USERS ──
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'student',   -- student | mentor | admin
        faculty TEXT,
        course INTEGER DEFAULT 1,
        specialty TEXT,
        hemis_id TEXT,
        rating INTEGER DEFAULT 0,
        achievements INTEGER DEFAULT 0,
        avatar TEXT DEFAULT '',
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── ATHLETES ──
    c.execute("""CREATE TABLE IF NOT EXISTS athletes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id),
        full_name TEXT NOT NULL,
        sport TEXT,
        faculty TEXT,
        course INTEGER,
        level TEXT DEFAULT 'university',  -- university|region|republic|international
        achievements TEXT DEFAULT '[]',
        medals_gold INTEGER DEFAULT 0,
        medals_silver INTEGER DEFAULT 0,
        medals_bronze INTEGER DEFAULT 0,
        rating_points INTEGER DEFAULT 0,
        coach TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── MENTORS ──
    c.execute("""CREATE TABLE IF NOT EXISTS mentors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id),
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

    # ── TALENTS ──
    c.execute("""CREATE TABLE IF NOT EXISTS talents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(id),
        full_name TEXT NOT NULL,
        faculty TEXT,
        specialty TEXT,
        course INTEGER,
        categories TEXT DEFAULT '[]',  -- science|sport|creative|social
        score INTEGER DEFAULT 0,
        achievements TEXT DEFAULT '[]',
        portfolio TEXT DEFAULT '[]',
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── HACKATHONS ──
    c.execute("""CREATE TABLE IF NOT EXISTS hackathons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'upcoming',  -- upcoming|open|closed
        prize TEXT,
        deadline TEXT,
        participants INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── EVENTS ──
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        location TEXT,
        event_date TEXT,
        event_time TEXT,
        category TEXT DEFAULT 'general',
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── NOTIFICATIONS ──
    c.execute("""CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT NOT NULL,
        body TEXT,
        read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── SESSIONS (chat/mentoring) ──
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mentor_id INTEGER REFERENCES mentors(id),
        student_id INTEGER REFERENCES users(id),
        subject TEXT,
        status TEXT DEFAULT 'pending',  -- pending|confirmed|done|cancelled
        session_date TEXT,
        session_time TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )""")

    # ── SETTINGS ──
    c.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )""")

    conn.commit()
    _seed_data(conn)
    conn.close()


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def _seed_data(conn):
    c = conn.cursor()
    # Admin
    c.execute("SELECT id FROM users WHERE username='admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users(username,password,full_name,role) VALUES(?,?,?,?)",
                  ("admin", _hash("admin123"), "Admin", "admin"))
        c.execute("INSERT INTO users(username,password,full_name,role,faculty,course,specialty,rating,achievements) VALUES(?,?,?,?,?,?,?,?,?)",
                  ("student1", _hash("1234"), "Ali Karimov", "student", "KTIF", 3, "Dasturlash", 847, 12))
        c.execute("INSERT INTO users(username,password,full_name,role,faculty,course,specialty,rating,achievements) VALUES(?,?,?,?,?,?,?,?,?)",
                  ("student2", _hash("1234"), "Zulfiya Tosheva", "student", "EIQ", 2, "AI/ML", 792, 9))

        # Athletes
        athletes = [
            ("Jasur Umarov", "Futbol", "KTIF", 3, "republic", 45, 10, 8, 320),
            ("Nilufar Rahimova", "Kurash", "EIQ", 2, "international", 30, 12, 9, 410),
            ("Bobur Mirzayev", "Basketbol", "MMF", 4, "region", 20, 5, 3, 180),
            ("Dilnoza Xasanova", "Voleybol", "KTIF", 1, "university", 10, 2, 1, 90),
            ("Sardor Ismoilov", "Shaxmat", "ITF", 3, "republic", 60, 8, 5, 280),
            ("Feruza Nazarova", "Tennis", "EIQ", 2, "region", 15, 3, 2, 120),
        ]
        for a in athletes:
            c.execute("""INSERT INTO athletes(full_name,sport,faculty,course,level,
                         medals_gold,medals_silver,medals_bronze,rating_points)
                         VALUES(?,?,?,?,?,?,?,?,?)""", a)

        # Mentors
        mentors_data = [
            ("Kamol Tursunov", '["Python","Machine Learning","Data Science"]', 4.9, 124, 87, 8, "10+ yil tajriba"),
            ("Sarvar Qodirov", '["JavaScript","React","Node.js"]', 4.8, 98, 64, 6, "Full-stack developer"),
            ("Malika Ergasheva", '["UI/UX Design","Figma","Adobe XD"]', 4.7, 76, 52, 5, "Product designer"),
            ("Nodir Kalandarov", '["C++","Algorithms","Data Structures"]', 4.6, 89, 70, 7, "Competitive programmer"),
        ]
        for m in mentors_data:
            c.execute("""INSERT INTO mentors(full_name,subjects,rating,sessions_total,
                         students_total,experience_years,bio)
                         VALUES(?,?,?,?,?,?,?)""", m)

        # Talents
        talents_data = [
            ("Ali Karimov", "KTIF", "Dasturlash", 3, '["science","creative"]', 920),
            ("Zulfiya Tosheva", "EIQ", "AI/ML", 2, '["science"]', 875),
            ("Jasur Umarov", "KTIF", "Dasturlash", 3, '["sport"]', 830),
            ("Nilufar Rahimova", "EIQ", "Moliya", 2, '["sport","social"]', 810),
            ("Sardor Ismoilov", "ITF", "Kiberjournalistika", 3, '["science","sport"]', 790),
            ("Oybek Normatov", "MMF", "Matematika", 4, '["science"]', 760),
            ("Dilnoza Xasanova", "KTIF", "Dasturlash", 1, '["sport","creative"]', 720),
            ("Kamola Mirzayeva", "HF", "Pedagogika", 2, '["social","creative"]', 695),
        ]
        for t in talents_data:
            c.execute("""INSERT INTO talents(full_name,faculty,specialty,course,categories,score)
                         VALUES(?,?,?,?,?,?)""", t)

        # Hackathons
        c.execute("""INSERT INTO hackathons(title,description,status,prize,deadline,participants)
                     VALUES(?,?,?,?,?,?)""",
                  ("TATU Hackathon 2025", "Aqlli shahar yechimlarini yaratish", "open",
                   "10,000,000 so'm", "2025-08-15", 48))
        c.execute("""INSERT INTO hackathons(title,description,status,prize,deadline,participants)
                     VALUES(?,?,?,?,?,?)""",
                  ("AI Challenge", "Sun'iy intellekt loyihalari musobaqasi", "upcoming",
                   "5,000,000 so'm", "2025-09-01", 0))

        # Events
        events_data = [
            ("TATU Sport Festivali", "Yillik sport festivali", "Sport kompleksi", "2025-07-20", "10:00", "sport"),
            ("Hackathon 2025", "Dasturlash musobaqasi", "A blok, 3-qavat", "2025-08-15", "09:00", "it"),
            ("Ilmiy konferensiya", "Talabalar ilmiy ishlari", "Konferensiya zali", "2025-07-25", "09:00", "science"),
            ("Mentor Training", "Mentorlik dasturi ta'lim", "B blok", "2025-07-18", "14:00", "education"),
        ]
        for ev in events_data:
            c.execute("""INSERT INTO events(title,description,location,event_date,event_time,category)
                         VALUES(?,?,?,?,?,?)""", ev)

        # Settings
        settings_data = [
            ("site_name", "S_TATU Platform"),
            ("university", "Samarqand TATU"),
            ("total_students", "8420"),
            ("total_athletes", "312"),
            ("total_mentors", "48"),
            ("total_talents", "156"),
            ("registration_open", "1"),
            ("maintenance", "0"),
        ]
        for s in settings_data:
            c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", s)

        conn.commit()
