"""
SAMdu Loyiha — Flask Backend
Ishga tushirish: python app.py
"""
import os, hashlib, json
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, flash)
from data.db import get_db, init_db, DB_PATH

app = Flask(__name__)
app.secret_key = "samdu_secret_key_2025"

BASE = os.path.dirname(__file__)


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


# ── AUTH DECORATORS ────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── HELPERS ───────────────────────────────────────────────────
def db_query(sql, params=(), one=False):
    conn = get_db()
    cur = conn.execute(sql, params)
    rows = cur.fetchone() if one else cur.fetchall()
    conn.close()
    return rows


def db_exec(sql, params=()):
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    last_id = cur.lastrowid
    conn.close()
    return last_id


def get_setting(key, default=""):
    row = db_query("SELECT value FROM settings WHERE key=?", (key,), one=True)
    return row["value"] if row else default


def get_stats():
    return {
        "students":  db_query("SELECT COUNT(*) as n FROM users WHERE role='student'", one=True)["n"],
        "athletes":  db_query("SELECT COUNT(*) as n FROM athletes", one=True)["n"],
        "mentors":   db_query("SELECT COUNT(*) as n FROM mentors", one=True)["n"],
        "talents":   db_query("SELECT COUNT(*) as n FROM talents", one=True)["n"],
        "hackathons":db_query("SELECT COUNT(*) as n FROM hackathons", one=True)["n"],
        "events":    db_query("SELECT COUNT(*) as n FROM events", one=True)["n"],
    }


# ═══════════════════════════════════════════════════════════════
# PUBLIC PAGES
# ═══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    stats = get_stats()
    top_athletes = db_query("""SELECT * FROM athletes ORDER BY rating_points DESC LIMIT 6""")
    top_talents  = db_query("""SELECT * FROM talents ORDER BY score DESC LIMIT 8""")
    events       = db_query("""SELECT * FROM events WHERE active=1 ORDER BY event_date LIMIT 4""")
    hackathons   = db_query("""SELECT * FROM hackathons ORDER BY created_at DESC LIMIT 3""")
    return render_template("index.html",
        stats=stats, top_athletes=top_athletes,
        top_talents=top_talents, events=events,
        hackathons=hackathons, site=get_setting("site_name", "S_TATU"))


# ── SPORT ─────────────────────────────────────────────────────
@app.route("/sport")
def sport():
    sport_filter = request.args.get("sport", "")
    level_filter = request.args.get("level", "")
    query = "SELECT * FROM athletes WHERE 1=1"
    params = []
    if sport_filter:
        query += " AND sport=?"; params.append(sport_filter)
    if level_filter:
        query += " AND level=?"; params.append(level_filter)
    query += " ORDER BY rating_points DESC"
    athletes = db_query(query, params)
    sports_list = db_query("SELECT DISTINCT sport FROM athletes ORDER BY sport")
    return render_template("sport.html", athletes=athletes,
                           sports_list=sports_list,
                           sport_filter=sport_filter, level_filter=level_filter)


@app.route("/sport/athlete/<int:aid>")
def athlete_detail(aid):
    athlete = db_query("SELECT * FROM athletes WHERE id=?", (aid,), one=True)
    if not athlete:
        return redirect(url_for("sport"))
    return render_template("athlete.html", athlete=athlete)


# ── STEMATE (Mentorlik) ───────────────────────────────────────
@app.route("/stemate")
def stemate():
    subj_filter = request.args.get("subject", "")
    mentors = db_query("SELECT * FROM mentors WHERE available=1 ORDER BY rating DESC")
    # Filter by subject
    if subj_filter:
        mentors = [m for m in mentors if subj_filter.lower() in m["subjects"].lower()]
    return render_template("stemate.html", mentors=mentors, subj_filter=subj_filter)


@app.route("/stemate/mentor/<int:mid>")
def mentor_detail(mid):
    mentor = db_query("SELECT * FROM mentors WHERE id=?", (mid,), one=True)
    if not mentor:
        return redirect(url_for("stemate"))
    sessions = db_query("""SELECT s.*, u.full_name as student_name
                            FROM sessions s LEFT JOIN users u ON s.student_id=u.id
                            WHERE s.mentor_id=? ORDER BY s.created_at DESC LIMIT 5""", (mid,))
    return render_template("mentor.html", mentor=mentor, sessions=sessions)


@app.route("/stemate/book/<int:mid>", methods=["POST"])
@login_required
def book_session(mid):
    subject = request.form.get("subject", "")
    date    = request.form.get("date", "")
    time    = request.form.get("time", "")
    db_exec("""INSERT INTO sessions(mentor_id,student_id,subject,session_date,session_time)
               VALUES(?,?,?,?,?)""",
            (mid, session["user_id"], subject, date, time))
    flash("Sessiya muvaffaqiyatli band qilindi!", "success")
    return redirect(url_for("mentor_detail", mid=mid))


# ── TALENTHUB ─────────────────────────────────────────────────
@app.route("/talenthub")
def talenthub():
    cat_filter = request.args.get("cat", "")
    query = "SELECT * FROM talents WHERE 1=1"
    params = []
    if cat_filter:
        query += " AND categories LIKE ?"
        params.append(f"%{cat_filter}%")
    query += " ORDER BY score DESC"
    talents = db_query(query, params)
    return render_template("talenthub.html", talents=talents, cat_filter=cat_filter)


# ── HACKATHONS ────────────────────────────────────────────────
@app.route("/hackathons")
def hackathons():
    hacks = db_query("SELECT * FROM hackathons ORDER BY created_at DESC")
    return render_template("hackathons.html", hackathons=hacks)


# ── EVENTS ────────────────────────────────────────────────────
@app.route("/events")
def events():
    evts = db_query("SELECT * FROM events WHERE active=1 ORDER BY event_date")
    return render_template("events.html", events=evts)


# ═══════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        user = db_query(
            "SELECT * FROM users WHERE username=? AND password=? AND active=1",
            (username, _hash(password)), one=True)
        if user:
            session["user_id"]   = user["id"]
            session["username"]  = user["username"]
            session["full_name"] = user["full_name"]
            session["role"]      = user["role"]
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        error = "Login yoki parol noto'g'ri!"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        full_name= request.form.get("full_name", "").strip()
        faculty  = request.form.get("faculty", "").strip()
        course   = int(request.form.get("course", 1))
        specialty= request.form.get("specialty", "").strip()
        # Unique check
        existing = db_query("SELECT id FROM users WHERE username=?", (username,), one=True)
        if existing:
            return render_template("login.html", error="Bu username allaqachon mavjud!", tab="register")
        db_exec("""INSERT INTO users(username,password,full_name,faculty,course,specialty)
                   VALUES(?,?,?,?,?,?)""",
                (username, _hash(password), full_name, faculty, course, specialty))
        flash("Ro'yxatdan o'tish muvaffaqiyatli! Endi kiring.", "success")
        return redirect(url_for("login"))
    return render_template("login.html", tab="register")


# ═══════════════════════════════════════════════════════════════
# STUDENT DASHBOARD
# ═══════════════════════════════════════════════════════════════

@app.route("/dashboard")
@login_required
def dashboard():
    user = db_query("SELECT * FROM users WHERE id=?", (session["user_id"],), one=True)
    notifs = db_query("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 5",
                      (session["user_id"],))
    unread = db_query("SELECT COUNT(*) as n FROM notifications WHERE user_id=? AND read=0",
                      (session["user_id"],), one=True)["n"]
    my_sessions = db_query("""SELECT s.*, m.full_name as mentor_name
                               FROM sessions s LEFT JOIN mentors m ON s.mentor_id=m.id
                               WHERE s.student_id=? ORDER BY s.created_at DESC LIMIT 5""",
                           (session["user_id"],))
    return render_template("dashboard.html",
                           user=user, notifs=notifs,
                           unread=unread, my_sessions=my_sessions)


# ═══════════════════════════════════════════════════════════════
# ADMIN PANEL
# ═══════════════════════════════════════════════════════════════

@app.route("/admin")
@admin_required
def admin_dashboard():
    stats = get_stats()
    recent_users  = db_query("SELECT * FROM users ORDER BY created_at DESC LIMIT 8")
    recent_events = db_query("SELECT * FROM events ORDER BY created_at DESC LIMIT 5")
    settings_all  = db_query("SELECT * FROM settings")
    return render_template("admin.html",
                           stats=stats,
                           recent_users=recent_users,
                           recent_events=recent_events,
                           settings={r["key"]: r["value"] for r in settings_all},
                           page="dashboard")


# ── ADMIN: USERS ──────────────────────────────────────────────
@app.route("/admin/users")
@admin_required
def admin_users():
    search = request.args.get("q", "")
    role   = request.args.get("role", "")
    query  = "SELECT * FROM users WHERE 1=1"
    params = []
    if search:
        query += " AND (full_name LIKE ? OR username LIKE ?)"
        params += [f"%{search}%", f"%{search}%"]
    if role:
        query += " AND role=?"; params.append(role)
    query += " ORDER BY created_at DESC"
    users = db_query(query, params)
    return render_template("admin.html", users=users,
                           search=search, role_filter=role, page="users")


@app.route("/admin/users/add", methods=["POST"])
@admin_required
def admin_add_user():
    un  = request.form.get("username", "").strip()
    pw  = request.form.get("password", "1234")
    fn  = request.form.get("full_name", "").strip()
    rl  = request.form.get("role", "student")
    fac = request.form.get("faculty", "")
    db_exec("INSERT INTO users(username,password,full_name,role,faculty) VALUES(?,?,?,?,?)",
            (un, _hash(pw), fn, rl, fac))
    flash(f"{fn} qo'shildi!", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/toggle/<int:uid>", methods=["POST"])
@admin_required
def admin_toggle_user(uid):
    user = db_query("SELECT active FROM users WHERE id=?", (uid,), one=True)
    if user:
        new_val = 0 if user["active"] else 1
        db_exec("UPDATE users SET active=? WHERE id=?", (new_val, uid))
    return redirect(url_for("admin_users"))


@app.route("/admin/users/delete/<int:uid>", methods=["POST"])
@admin_required
def admin_delete_user(uid):
    db_exec("DELETE FROM users WHERE id=?", (uid,))
    flash("Foydalanuvchi o'chirildi.", "info")
    return redirect(url_for("admin_users"))


# ── ADMIN: ATHLETES ───────────────────────────────────────────
@app.route("/admin/athletes")
@admin_required
def admin_athletes():
    athletes = db_query("SELECT * FROM athletes ORDER BY rating_points DESC")
    return render_template("admin.html", athletes=athletes, page="athletes")


@app.route("/admin/athletes/add", methods=["POST"])
@admin_required
def admin_add_athlete():
    fn     = request.form.get("full_name", "").strip()
    sport  = request.form.get("sport", "").strip()
    fac    = request.form.get("faculty", "")
    course = int(request.form.get("course", 1))
    level  = request.form.get("level", "university")
    db_exec("""INSERT INTO athletes(full_name,sport,faculty,course,level)
               VALUES(?,?,?,?,?)""", (fn, sport, fac, course, level))
    flash(f"{fn} sportchi qo'shildi!", "success")
    return redirect(url_for("admin_athletes"))


@app.route("/admin/athletes/delete/<int:aid>", methods=["POST"])
@admin_required
def admin_delete_athlete(aid):
    db_exec("DELETE FROM athletes WHERE id=?", (aid,))
    return redirect(url_for("admin_athletes"))


# ── ADMIN: MENTORS ────────────────────────────────────────────
@app.route("/admin/mentors")
@admin_required
def admin_mentors():
    mentors = db_query("SELECT * FROM mentors ORDER BY rating DESC")
    return render_template("admin.html", mentors=mentors, page="mentors")


@app.route("/admin/mentors/add", methods=["POST"])
@admin_required
def admin_add_mentor():
    fn   = request.form.get("full_name", "").strip()
    subj = request.form.get("subjects", "[]")
    bio  = request.form.get("bio", "")
    exp  = int(request.form.get("experience_years", 1))
    db_exec("""INSERT INTO mentors(full_name,subjects,bio,experience_years)
               VALUES(?,?,?,?)""", (fn, subj, bio, exp))
    flash(f"{fn} mentor qo'shildi!", "success")
    return redirect(url_for("admin_mentors"))


@app.route("/admin/mentors/delete/<int:mid>", methods=["POST"])
@admin_required
def admin_delete_mentor(mid):
    db_exec("DELETE FROM mentors WHERE id=?", (mid,))
    return redirect(url_for("admin_mentors"))


# ── ADMIN: EVENTS ─────────────────────────────────────────────
@app.route("/admin/events")
@admin_required
def admin_events():
    evts = db_query("SELECT * FROM events ORDER BY event_date DESC")
    return render_template("admin.html", events=evts, page="events")


@app.route("/admin/events/add", methods=["POST"])
@admin_required
def admin_add_event():
    title = request.form.get("title", "").strip()
    desc  = request.form.get("description", "")
    loc   = request.form.get("location", "")
    date  = request.form.get("event_date", "")
    time  = request.form.get("event_time", "")
    cat   = request.form.get("category", "general")
    db_exec("""INSERT INTO events(title,description,location,event_date,event_time,category)
               VALUES(?,?,?,?,?,?)""", (title, desc, loc, date, time, cat))
    flash(f"'{title}' tadbirı qo'shildi!", "success")
    return redirect(url_for("admin_events"))


@app.route("/admin/events/delete/<int:eid>", methods=["POST"])
@admin_required
def admin_delete_event(eid):
    db_exec("DELETE FROM events WHERE id=?", (eid,))
    return redirect(url_for("admin_events"))


# ── ADMIN: HACKATHONS ─────────────────────────────────────────
@app.route("/admin/hackathons")
@admin_required
def admin_hackathons():
    hacks = db_query("SELECT * FROM hackathons ORDER BY created_at DESC")
    return render_template("admin.html", hackathons=hacks, page="hackathons")


@app.route("/admin/hackathons/add", methods=["POST"])
@admin_required
def admin_add_hackathon():
    title = request.form.get("title", "").strip()
    desc  = request.form.get("description", "")
    prize = request.form.get("prize", "")
    dl    = request.form.get("deadline", "")
    stat  = request.form.get("status", "upcoming")
    db_exec("""INSERT INTO hackathons(title,description,prize,deadline,status)
               VALUES(?,?,?,?,?)""", (title, desc, prize, dl, stat))
    flash(f"'{title}' hackathon qo'shildi!", "success")
    return redirect(url_for("admin_hackathons"))


@app.route("/admin/hackathons/delete/<int:hid>", methods=["POST"])
@admin_required
def admin_delete_hackathon(hid):
    db_exec("DELETE FROM hackathons WHERE id=?", (hid,))
    return redirect(url_for("admin_hackathons"))


# ── ADMIN: TALENTS ────────────────────────────────────────────
@app.route("/admin/talents")
@admin_required
def admin_talents():
    talents = db_query("SELECT * FROM talents ORDER BY score DESC")
    return render_template("admin.html", talents=talents, page="talents")


@app.route("/admin/talents/delete/<int:tid>", methods=["POST"])
@admin_required
def admin_delete_talent(tid):
    db_exec("DELETE FROM talents WHERE id=?", (tid,))
    return redirect(url_for("admin_talents"))


# ── ADMIN: NOTIFICATIONS ──────────────────────────────────────
@app.route("/admin/notifications", methods=["GET", "POST"])
@admin_required
def admin_notifications():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body  = request.form.get("body", "").strip()
        target= request.form.get("target", "all")
        conn  = get_db()
        if target == "all":
            users = conn.execute("SELECT id FROM users WHERE role='student'").fetchall()
            for u in users:
                conn.execute("INSERT INTO notifications(user_id,title,body) VALUES(?,?,?)",
                             (u["id"], title, body))
        conn.commit()
        conn.close()
        flash(f"Xabarnoma yuborildi: {len(users) if target=='all' else 1} foydalanuvchiga", "success")
        return redirect(url_for("admin_notifications"))
    notifs = db_query("SELECT n.*,u.full_name FROM notifications n LEFT JOIN users u ON n.user_id=u.id ORDER BY n.created_at DESC LIMIT 30")
    return render_template("admin.html", notifs=notifs, page="notifications")


# ── ADMIN: SETTINGS ───────────────────────────────────────────
@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        for key in ["site_name", "university", "registration_open", "maintenance"]:
            val = request.form.get(key, "")
            db_exec("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, val))
        flash("Sozlamalar saqlandi!", "success")
        return redirect(url_for("admin_settings"))
    settings_all = db_query("SELECT * FROM settings")
    return render_template("admin.html",
                           settings={r["key"]: r["value"] for r in settings_all},
                           page="settings")


# ═══════════════════════════════════════════════════════════════
# API (JSON)
# ═══════════════════════════════════════════════════════════════

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/athletes")
def api_athletes():
    athletes = db_query("SELECT * FROM athletes ORDER BY rating_points DESC")
    return jsonify([dict(a) for a in athletes])


@app.route("/api/talents")
def api_talents():
    talents = db_query("SELECT * FROM talents ORDER BY score DESC")
    return jsonify([dict(t) for t in talents])


@app.route("/api/events")
def api_events():
    evts = db_query("SELECT * FROM events WHERE active=1 ORDER BY event_date")
    return jsonify([dict(e) for e in evts])


@app.route("/api/notifications/mark-read", methods=["POST"])
@login_required
def mark_notifications_read():
    db_exec("UPDATE notifications SET read=1 WHERE user_id=?", (session["user_id"],))
    return jsonify({"ok": True})


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 55)
    print("  🎓  SAMdu / S_TATU Platform")
    print("=" * 55)
    print(f"  🌐  URL    : http://localhost:5000")
    print(f"  🔐  Admin  : http://localhost:5000/admin")
    print(f"  👤  Login  : admin / admin123")
    print("=" * 55)
    if not os.path.exists(DB_PATH):
        print("  📦  Ma'lumotlar bazasi yaratilmoqda...")
    init_db()
    print("  ✅  Tayyor! Brauzer avtomatik ochiladi...\n")
    import threading, webbrowser, time
    def open_browser():
        time.sleep(1.2)
        webbrowser.open("http://localhost:5000")
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True)
