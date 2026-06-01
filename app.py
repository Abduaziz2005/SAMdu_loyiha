"""
SAMdu S_TATU Platform — Flask Backend v2.0
Xavfsizlik: CSRF, Rate limiting, Salted hash, Maintenance, Sanitizatsiya
Admin: 10+ yangi funksiya
"""
import os, json, secrets, csv, io, re
from functools import wraps
from datetime import datetime, timedelta
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, flash, make_response,
                   send_file, abort)
from data.db import (get_db, init_db, DB_PATH,
                     _hash, _hash_password, verify_password)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY  = True,
    SESSION_COOKIE_SAMESITE  = "Lax",
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8),
    MAX_CONTENT_LENGTH       = 5 * 1024 * 1024,   # 5 MB
)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


# ═══════════════════════════════════════════════════════════════
# HELPERS — DB shortcuts
# ═══════════════════════════════════════════════════════════════
def db_query(sql, params=(), one=False):
    conn = get_db()
    try:
        cur = conn.execute(sql, params)
        return cur.fetchone() if one else cur.fetchall()
    finally:
        conn.close()

def db_exec(sql, params=()):
    conn = get_db()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()

def get_setting(key, default=""):
    row = db_query("SELECT value FROM settings WHERE key=?", (key,), one=True)
    return row["value"] if row else default

def get_stats():
    return {
        "students":   db_query("SELECT COUNT(*) as n FROM users WHERE role='student'", one=True)["n"],
        "athletes":   db_query("SELECT COUNT(*) as n FROM athletes", one=True)["n"],
        "mentors":    db_query("SELECT COUNT(*) as n FROM mentors", one=True)["n"],
        "talents":    db_query("SELECT COUNT(*) as n FROM talents", one=True)["n"],
        "hackathons": db_query("SELECT COUNT(*) as n FROM hackathons", one=True)["n"],
        "events":     db_query("SELECT COUNT(*) as n FROM events", one=True)["n"],
        "sessions":   db_query("SELECT COUNT(*) as n FROM sessions", one=True)["n"],
        "announcements": db_query("SELECT COUNT(*) as n FROM announcements WHERE active=1", one=True)["n"],
    }

def sanitize(text, max_len=500):
    """XSS va injection uchun asosiy sanitizatsiya"""
    if not text:
        return ""
    text = str(text).strip()[:max_len]
    # HTML special chars
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace('"', "&quot;").replace("'", "&#x27;")
    return text

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def get_client_ip():
    return (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP", "")
            or request.remote_addr or "unknown")


# ═══════════════════════════════════════════════════════════════
# XAVFSIZLIK — CSRF
# ═══════════════════════════════════════════════════════════════
def generate_csrf():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]

def validate_csrf():
    token = (request.form.get("_csrf_token") or
             request.headers.get("X-CSRF-Token", ""))
    return token and token == session.get("_csrf")

def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            if not validate_csrf():
                audit_log_write("csrf_fail", details=f"endpoint={request.endpoint}")
                flash("Xavfsizlik xatosi: CSRF token noto'g'ri. Sahifani yangilang.", "danger")
                return redirect(request.referrer or url_for("index"))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf}

# ═══════════════════════════════════════════════════════════════
# XAVFSIZLIK — RATE LIMITING
# ═══════════════════════════════════════════════════════════════
def is_rate_limited(endpoint="login", max_req=10, window_sec=60):
    ip = get_client_ip()
    conn = get_db()
    try:
        now   = datetime.utcnow()
        start = (now - timedelta(seconds=window_sec)).strftime("%Y-%m-%d %H:%M:%S")
        row = conn.execute(
            "SELECT id, request_count, blocked_until FROM rate_limits WHERE ip_address=? AND endpoint=?",
            (ip, endpoint)).fetchone()
        # Blocked?
        if row and row["blocked_until"]:
            blocked_until = row["blocked_until"]
            if blocked_until > now.strftime("%Y-%m-%d %H:%M:%S"):
                return True
        # Count in window
        count_row = conn.execute(
            "SELECT COUNT(*) as n FROM login_attempts WHERE ip_address=? AND created_at > ? AND success=0",
            (ip, start)).fetchone()
        if count_row and count_row["n"] >= max_req:
            block_until = (now + timedelta(minutes=int(get_setting("lockout_minutes", "30")))).strftime("%Y-%m-%d %H:%M:%S")
            if row:
                conn.execute("UPDATE rate_limits SET blocked_until=? WHERE id=?", (block_until, row["id"]))
            else:
                conn.execute("INSERT INTO rate_limits(ip_address,endpoint,blocked_until) VALUES(?,?,?)",
                             (ip, endpoint, block_until))
            conn.commit()
            return True
        return False
    finally:
        conn.close()

# ═══════════════════════════════════════════════════════════════
# XAVFSIZLIK — AUDIT LOG
# ═══════════════════════════════════════════════════════════════
def audit_log_write(action, target_type="", target_id=0, details=""):
    try:
        uid  = session.get("user_id", 0)
        uname= session.get("username", "anonymous")
        ip   = get_client_ip()
        ua   = request.headers.get("User-Agent", "")[:200]
        db_exec(
            """INSERT INTO audit_log(user_id,username,action,target_type,target_id,details,ip_address,user_agent)
               VALUES(?,?,?,?,?,?,?,?)""",
            (uid, uname, action, target_type, target_id, details[:500], ip, ua))
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# XAVFSIZLIK — DEKORATORLAR
# ═══════════════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Kirish talab etiladi.", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            audit_log_write("unauthorized_access", details=request.path)
            flash("Admin huquqi talab etiladi.", "danger")
            return redirect(url_for("login"))
        # Active tekshiruv
        user = db_query("SELECT active FROM users WHERE id=?", (session.get("user_id"),), one=True)
        if not user or not user["active"]:
            session.clear()
            flash("Hisobingiz faol emas.", "danger")
            return redirect(url_for("login"))
        # IP restriction (agar sozlangan bo'lsa)
        allowed_ips = get_setting("allowed_admin_ips", "").strip()
        if allowed_ips:
            ip_list = [x.strip() for x in allowed_ips.split(",") if x.strip()]
            if ip_list and get_client_ip() not in ip_list:
                audit_log_write("blocked_ip", details=f"ip={get_client_ip()}")
                abort(403)
        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════════════════════════════
# XAVFSIZLIK — BEFORE REQUEST (maintenance, headers)
# ═══════════════════════════════════════════════════════════════
@app.before_request
def before_req():
    # Maintenance mode
    if get_setting("maintenance") == "1":
        exempt = ["/admin", "/login", "/logout", "/static"]
        if not any(request.path.startswith(p) for p in exempt):
            msg = get_setting("maintenance_msg", "Tizim texnik ishlar olib bormoqda.")
            return render_template("maintenance.html", msg=msg), 503
    # Session permanent
    session.permanent = True

@app.after_request
def security_headers(response):
    """Security headers — XSS, Clickjacking va boshqa hujumlardan himoya"""
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "SAMEORIGIN"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
        "https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
        "https://fonts.gstatic.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    # Cache: admin sahifalari cache bo'lmasin
    if request.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"]        = "no-cache"
    return response

@app.errorhandler(403)
def e403(e): return render_template("error.html", code=403, msg="Ruxsat etilmagan"), 403

@app.errorhandler(404)
def e404(e): return render_template("error.html", code=404, msg="Sahifa topilmadi"), 404

@app.errorhandler(429)
def e429(e): return render_template("error.html", code=429, msg="Juda ko'p so'rov"), 429

@app.errorhandler(500)
def e500(e):
    audit_log_write("server_error", details=str(e)[:200])
    return render_template("error.html", code=500, msg="Ichki server xatosi"), 500


# ═══════════════════════════════════════════════════════════════
# PUBLIC PAGES
# ═══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    stats        = get_stats()
    top_athletes = db_query("SELECT * FROM athletes ORDER BY rating_points DESC LIMIT 6")
    top_talents  = db_query("SELECT * FROM talents ORDER BY score DESC LIMIT 8")
    events       = db_query("SELECT * FROM events WHERE active=1 ORDER BY event_date LIMIT 4")
    hackathons   = db_query("SELECT * FROM hackathons ORDER BY created_at DESC LIMIT 3")
    announcements= db_query("SELECT * FROM announcements WHERE active=1 ORDER BY pinned DESC,created_at DESC LIMIT 3")
    return render_template("index.html",
        stats=stats, top_athletes=top_athletes, top_talents=top_talents,
        events=events, hackathons=hackathons, announcements=announcements,
        site=get_setting("site_name","S_TATU"))

@app.route("/sport")
def sport():
    sport_filter = sanitize(request.args.get("sport",""), 50)
    level_filter = sanitize(request.args.get("level",""), 30)
    q = "SELECT * FROM athletes WHERE 1=1"
    p = []
    if sport_filter: q += " AND sport=?";  p.append(sport_filter)
    if level_filter: q += " AND level=?";  p.append(level_filter)
    q += " ORDER BY rating_points DESC"
    athletes    = db_query(q, p)
    sports_list = db_query("SELECT DISTINCT sport FROM athletes ORDER BY sport")
    return render_template("sport.html", athletes=athletes, sports_list=sports_list,
                           sport_filter=sport_filter, level_filter=level_filter)

@app.route("/sport/athlete/<int:aid>")
def athlete_detail(aid):
    athlete = db_query("SELECT * FROM athletes WHERE id=?", (aid,), one=True)
    if not athlete: return redirect(url_for("sport"))
    return render_template("athlete.html", athlete=athlete)

@app.route("/stemate")
def stemate():
    subj_filter = sanitize(request.args.get("subject",""), 50)
    mentors = db_query("SELECT * FROM mentors WHERE available=1 ORDER BY rating DESC")
    if subj_filter:
        mentors = [m for m in mentors if subj_filter.lower() in m["subjects"].lower()]
    return render_template("stemate.html", mentors=mentors, subj_filter=subj_filter)

@app.route("/stemate/mentor/<int:mid>")
def mentor_detail(mid):
    mentor = db_query("SELECT * FROM mentors WHERE id=?", (mid,), one=True)
    if not mentor: return redirect(url_for("stemate"))
    sessions = db_query("""SELECT s.*,u.full_name as student_name
                            FROM sessions s LEFT JOIN users u ON s.student_id=u.id
                            WHERE s.mentor_id=? ORDER BY s.created_at DESC LIMIT 5""", (mid,))
    return render_template("mentor.html", mentor=mentor, sessions=sessions)

@app.route("/stemate/book/<int:mid>", methods=["POST"])
@login_required
@csrf_protect
def book_session(mid):
    subject = sanitize(request.form.get("subject",""), 100)
    date    = sanitize(request.form.get("date",""), 20)
    time    = sanitize(request.form.get("time",""), 10)
    dur     = int(request.form.get("duration_min", 60) or 60)
    db_exec("INSERT INTO sessions(mentor_id,student_id,subject,session_date,session_time,duration_min) VALUES(?,?,?,?,?,?)",
            (mid, session["user_id"], subject, date, time, dur))
    # Mentor sessions_total update
    db_exec("UPDATE mentors SET sessions_total=sessions_total+1 WHERE id=?", (mid,))
    audit_log_write("book_session", "session", mid, f"mentor={mid} student={session['user_id']}")
    flash("Sessiya muvaffaqiyatli band qilindi!", "success")
    return redirect(url_for("mentor_detail", mid=mid))

@app.route("/talenthub")
def talenthub():
    cat_filter = sanitize(request.args.get("cat",""), 30)
    q = "SELECT * FROM talents WHERE 1=1"
    p = []
    if cat_filter: q += " AND categories LIKE ?"; p.append(f"%{cat_filter}%")
    q += " ORDER BY score DESC"
    talents = db_query(q, p)
    return render_template("talenthub.html", talents=talents, cat_filter=cat_filter)

@app.route("/hackathons")
def hackathons():
    hacks = db_query("SELECT * FROM hackathons ORDER BY created_at DESC")
    return render_template("hackathons.html", hackathons=hacks)

@app.route("/events")
def events():
    evts = db_query("SELECT * FROM events WHERE active=1 ORDER BY event_date")
    return render_template("events.html", events=evts)


# ═══════════════════════════════════════════════════════════════
# AUTH — Kuchaytirish: salted hash, rate limit, audit
# ═══════════════════════════════════════════════════════════════
@app.route("/login", methods=["GET","POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("admin_dashboard") if session.get("role")=="admin" else url_for("dashboard"))
    error = None
    if request.method == "POST":
        if not validate_csrf():
            error = "Xavfsizlik xatosi. Sahifani yangilang."
        else:
            username = sanitize(request.form.get("username",""), 50)
            password = request.form.get("password","")
            ip       = get_client_ip()
            ua       = request.headers.get("User-Agent","")[:200]
            max_att  = int(get_setting("max_login_attempts","5"))

            # Rate limit tekshiruv
            if is_rate_limited("login", max_req=max_att):
                minutes = get_setting("lockout_minutes","30")
                error = f"Juda ko'p urinish. {minutes} daqiqadan keyin urinib ko'ring."
                db_exec("INSERT INTO login_attempts(username,ip_address,success,user_agent) VALUES(?,?,0,?)",
                        (username, ip, ua))
            else:
                user = db_query("SELECT * FROM users WHERE username=? AND active=1", (username,), one=True)
                ok = False
                if user:
                    salt = user["password_salt"] or ""
                    ok = verify_password(password, user["password"], salt)
                    # Fallback: eski unsalted hash
                    if not ok and not salt:
                        ok = (user["password"] == _hash(password))
                        if ok:
                            # Migrate to salted
                            new_h, new_s = _hash_password(password)
                            db_exec("UPDATE users SET password=?,password_salt=? WHERE id=?",
                                    (new_h, new_s, user["id"]))
                db_exec("INSERT INTO login_attempts(username,ip_address,success,user_agent) VALUES(?,?,?,?)",
                        (username, ip, 1 if (user and ok) else 0, ua))
                if user and ok:
                    session.regenerate() if hasattr(session,"regenerate") else None
                    session["user_id"]   = user["id"]
                    session["username"]  = user["username"]
                    session["full_name"] = user["full_name"]
                    session["role"]      = user["role"]
                    db_exec("UPDATE users SET last_login=datetime('now'),login_count=login_count+1 WHERE id=?",
                            (user["id"],))
                    audit_log_write("login_success", "user", user["id"])
                    nxt = request.args.get("next","")
                    if user["role"] == "admin":
                        return redirect(url_for("admin_dashboard"))
                    return redirect(url_for("dashboard"))
                else:
                    error = "Login yoki parol noto'g'ri!"
                    audit_log_write("login_fail", details=f"username={username}")
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    audit_log_write("logout")
    session.clear()
    flash("Muvaffaqiyatli chiqdingiz.", "info")
    return redirect(url_for("index"))

@app.route("/register", methods=["GET","POST"])
@csrf_protect
def register():
    if get_setting("registration_open","1") != "1":
        flash("Ro'yxatdan o'tish hozircha yopiq.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        username  = sanitize(request.form.get("username",""), 30)
        password  = request.form.get("password","")
        full_name = sanitize(request.form.get("full_name",""), 80)
        faculty   = sanitize(request.form.get("faculty",""), 20)
        course    = int(request.form.get("course",1) or 1)
        specialty = sanitize(request.form.get("specialty",""), 80)
        # Validatsiya
        if not username or len(username) < 3:
            return render_template("login.html", error="Username kamida 3 belgi bo'lishi kerak.", tab="register")
        if not password or len(password) < 4:
            return render_template("login.html", error="Parol kamida 4 belgi bo'lishi kerak.", tab="register")
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return render_template("login.html", error="Username faqat lotin harflari, raqam va _ bo'lishi kerak.", tab="register")
        existing = db_query("SELECT id FROM users WHERE username=?", (username,), one=True)
        if existing:
            return render_template("login.html", error="Bu username allaqachon mavjud!", tab="register")
        hashed, salt = _hash_password(password)
        db_exec("INSERT INTO users(username,password,password_salt,full_name,faculty,course,specialty) VALUES(?,?,?,?,?,?,?)",
                (username, hashed, salt, full_name, faculty, course, specialty))
        audit_log_write("register", details=f"username={username}")
        flash("Ro'yxatdan o'tish muvaffaqiyatli! Endi kiring.", "success")
        return redirect(url_for("login"))
    return render_template("login.html", tab="register")


# ═══════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════
@app.route("/dashboard")
@login_required
def dashboard():
    user     = db_query("SELECT * FROM users WHERE id=?", (session["user_id"],), one=True)
    notifs   = db_query("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 10", (session["user_id"],))
    unread   = db_query("SELECT COUNT(*) as n FROM notifications WHERE user_id=? AND read=0", (session["user_id"],), one=True)["n"]
    my_sessions = db_query("""SELECT s.*,m.full_name as mentor_name
                               FROM sessions s LEFT JOIN mentors m ON s.mentor_id=m.id
                               WHERE s.student_id=? ORDER BY s.created_at DESC LIMIT 10""", (session["user_id"],))
    return render_template("dashboard.html", user=user, notifs=notifs, unread=unread, my_sessions=my_sessions)

@app.route("/dashboard/change-password", methods=["POST"])
@login_required
@csrf_protect
def change_password():
    old_pw  = request.form.get("old_password","")
    new_pw  = request.form.get("new_password","")
    conf_pw = request.form.get("confirm_password","")
    user = db_query("SELECT * FROM users WHERE id=?", (session["user_id"],), one=True)
    salt = user["password_salt"] or ""
    if not verify_password(old_pw, user["password"], salt) and _hash(old_pw) != user["password"]:
        flash("Eski parol noto'g'ri!", "danger")
        return redirect(url_for("dashboard"))
    if new_pw != conf_pw:
        flash("Yangi parollar mos emas!", "danger")
        return redirect(url_for("dashboard"))
    if len(new_pw) < 4:
        flash("Yangi parol kamida 4 belgi bo'lishi kerak!", "danger")
        return redirect(url_for("dashboard"))
    new_h, new_s = _hash_password(new_pw)
    db_exec("UPDATE users SET password=?,password_salt=? WHERE id=?", (new_h, new_s, session["user_id"]))
    audit_log_write("change_password", "user", session["user_id"])
    flash("Parol muvaffaqiyatli o'zgartirildi!", "success")
    return redirect(url_for("dashboard"))


# ═══════════════════════════════════════════════════════════════
# ADMIN — DASHBOARD
# ═══════════════════════════════════════════════════════════════
@app.route("/admin")
@admin_required
def admin_dashboard():
    stats        = get_stats()
    recent_users = db_query("SELECT * FROM users ORDER BY created_at DESC LIMIT 8")
    recent_events= db_query("SELECT * FROM events ORDER BY created_at DESC LIMIT 5")
    settings_all = db_query("SELECT * FROM settings")
    recent_audit = db_query("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 10")
    recent_logins= db_query("SELECT * FROM login_attempts ORDER BY created_at DESC LIMIT 8")
    pending_sess = db_query("SELECT COUNT(*) as n FROM sessions WHERE status='pending'", one=True)["n"]
    # Monthly registrations (last 6 months)
    monthly_reg  = db_query("""
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as cnt
        FROM users WHERE created_at >= date('now','-6 months')
        GROUP BY month ORDER BY month""")
    return render_template("admin.html",
        stats=stats, recent_users=recent_users, recent_events=recent_events,
        settings={r["key"]: r["value"] for r in settings_all},
        recent_audit=recent_audit, recent_logins=recent_logins,
        pending_sessions=pending_sess, monthly_reg=monthly_reg,
        page="dashboard")

# ═══════════════════════════════════════════════════════════════
# ADMIN — USERS (CRUD + edit + export)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/users")
@admin_required
def admin_users():
    search = sanitize(request.args.get("q",""), 80)
    role   = sanitize(request.args.get("role",""), 20)
    fac    = sanitize(request.args.get("faculty",""), 20)
    page   = int(request.args.get("p",1) or 1)
    per    = 20
    offset = (page - 1) * per
    q = "SELECT * FROM users WHERE 1=1"
    params = []
    if search:
        q += " AND (full_name LIKE ? OR username LIKE ? OR email LIKE ?)"
        params += [f"%{search}%"] * 3
    if role:    q += " AND role=?";    params.append(role)
    if fac:     q += " AND faculty=?"; params.append(fac)
    q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [per, offset]
    users = db_query(q, params)
    total = db_query("SELECT COUNT(*) as n FROM users", one=True)["n"]
    return render_template("admin.html", users=users, search=search, role_filter=role,
                           fac_filter=fac, page_num=page, total=total, per=per, page="users")

@app.route("/admin/users/add", methods=["POST"])
@admin_required
@csrf_protect
def admin_add_user():
    un  = sanitize(request.form.get("username",""), 30)
    pw  = request.form.get("password","1234")
    fn  = sanitize(request.form.get("full_name",""), 80)
    rl  = request.form.get("role","student")
    fac = sanitize(request.form.get("faculty",""), 20)
    eml = sanitize(request.form.get("email",""), 100)
    hashed, salt = _hash_password(pw)
    db_exec("INSERT INTO users(username,password,password_salt,full_name,role,faculty,email) VALUES(?,?,?,?,?,?,?)",
            (un, hashed, salt, fn, rl, fac, eml))
    audit_log_write("add_user", "user", 0, f"username={un} role={rl}")
    flash(f"'{fn}' qo'shildi!", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/edit/<int:uid>", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_edit_user(uid):
    user = db_query("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not user: return redirect(url_for("admin_users"))
    if request.method == "POST":
        fn  = sanitize(request.form.get("full_name",""), 80)
        rl  = request.form.get("role","student")
        fac = sanitize(request.form.get("faculty",""), 20)
        eml = sanitize(request.form.get("email",""), 100)
        phn = sanitize(request.form.get("phone",""), 20)
        crs = int(request.form.get("course",1) or 1)
        sp  = sanitize(request.form.get("specialty",""), 80)
        rat = int(request.form.get("rating",0) or 0)
        db_exec("UPDATE users SET full_name=?,role=?,faculty=?,email=?,phone=?,course=?,specialty=?,rating=? WHERE id=?",
                (fn, rl, fac, eml, phn, crs, sp, rat, uid))
        # Parol o'zgartirish (ixtiyoriy)
        new_pw = request.form.get("new_password","")
        if new_pw and len(new_pw) >= 4:
            new_h, new_s = _hash_password(new_pw)
            db_exec("UPDATE users SET password=?,password_salt=? WHERE id=?", (new_h, new_s, uid))
        audit_log_write("edit_user", "user", uid, f"fn={fn} role={rl}")
        flash(f"'{fn}' yangilandi!", "success")
        return redirect(url_for("admin_users"))
    return render_template("admin.html", edit_user=user, page="users_edit")

@app.route("/admin/users/toggle/<int:uid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_toggle_user(uid):
    if uid == session.get("user_id"):
        flash("O'zingizni bloklashingiz mumkin emas!", "danger")
        return redirect(url_for("admin_users"))
    user = db_query("SELECT active,full_name FROM users WHERE id=?", (uid,), one=True)
    if user:
        new_val = 0 if user["active"] else 1
        db_exec("UPDATE users SET active=? WHERE id=?", (new_val, uid))
        audit_log_write("toggle_user", "user", uid, f"active={new_val}")
        flash(f"'{user['full_name']}' {'faollashtirildi' if new_val else 'bloklandi'}.", "info")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/delete/<int:uid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_user(uid):
    if uid == session.get("user_id"):
        flash("O'zingizni o'chirishingiz mumkin emas!", "danger")
        return redirect(url_for("admin_users"))
    user = db_query("SELECT full_name FROM users WHERE id=?", (uid,), one=True)
    db_exec("DELETE FROM users WHERE id=?", (uid,))
    audit_log_write("delete_user", "user", uid, f"fn={user['full_name'] if user else ''}")
    flash("Foydalanuvchi o'chirildi.", "info")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/reset-password/<int:uid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_reset_password(uid):
    new_pw = request.form.get("new_password","1234")
    new_h, new_s = _hash_password(new_pw)
    db_exec("UPDATE users SET password=?,password_salt=? WHERE id=?", (new_h, new_s, uid))
    audit_log_write("reset_password","user", uid)
    flash("Parol muvaffaqiyatli yangilandi!", "success")
    return redirect(url_for("admin_edit_user", uid=uid))

@app.route("/admin/users/export")
@admin_required
def admin_export_users():
    users = db_query("SELECT id,username,full_name,role,faculty,course,specialty,email,phone,active,rating,created_at FROM users ORDER BY id")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Username","To'liq ism","Rol","Fakultet","Kurs","Mutaxassislik","Email","Telefon","Faol","Reyting","Yaratilgan"])
    for u in users:
        writer.writerow([u["id"],u["username"],u["full_name"],u["role"],u["faculty"],
                         u["course"],u["specialty"],u["email"],u["phone"],
                         "Ha" if u["active"] else "Yo'q",u["rating"],u["created_at"]])
    output.seek(0)
    audit_log_write("export_users")
    return make_response(output.getvalue(), 200,
                         {"Content-Type":"text/csv; charset=utf-8",
                          "Content-Disposition":"attachment; filename=users.csv"})


# ═══════════════════════════════════════════════════════════════
# ADMIN — ATHLETES (CRUD + edit)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/athletes")
@admin_required
def admin_athletes():
    athletes = db_query("SELECT * FROM athletes ORDER BY rating_points DESC")
    return render_template("admin.html", athletes=athletes, page="athletes")

@app.route("/admin/athletes/add", methods=["POST"])
@admin_required
@csrf_protect
def admin_add_athlete():
    fn    = sanitize(request.form.get("full_name",""), 80)
    sport = sanitize(request.form.get("sport",""), 50)
    fac   = sanitize(request.form.get("faculty",""), 20)
    crs   = int(request.form.get("course",1) or 1)
    lvl   = request.form.get("level","university")
    coach = sanitize(request.form.get("coach",""), 80)
    bio   = sanitize(request.form.get("bio",""), 300)
    mg    = int(request.form.get("medals_gold",0) or 0)
    ms    = int(request.form.get("medals_silver",0) or 0)
    mb    = int(request.form.get("medals_bronze",0) or 0)
    rp    = int(request.form.get("rating_points",0) or 0)
    db_exec("INSERT INTO athletes(full_name,sport,faculty,course,level,coach,bio,medals_gold,medals_silver,medals_bronze,rating_points) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (fn, sport, fac, crs, lvl, coach, bio, mg, ms, mb, rp))
    audit_log_write("add_athlete", details=f"fn={fn}")
    flash(f"'{fn}' sportchi qo'shildi!", "success")
    return redirect(url_for("admin_athletes"))

@app.route("/admin/athletes/edit/<int:aid>", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_edit_athlete(aid):
    ath = db_query("SELECT * FROM athletes WHERE id=?", (aid,), one=True)
    if not ath: return redirect(url_for("admin_athletes"))
    if request.method == "POST":
        db_exec("""UPDATE athletes SET full_name=?,sport=?,faculty=?,course=?,level=?,
                   coach=?,bio=?,medals_gold=?,medals_silver=?,medals_bronze=?,rating_points=?
                   WHERE id=?""",
                (sanitize(request.form.get("full_name",""),80),
                 sanitize(request.form.get("sport",""),50),
                 sanitize(request.form.get("faculty",""),20),
                 int(request.form.get("course",1) or 1),
                 request.form.get("level","university"),
                 sanitize(request.form.get("coach",""),80),
                 sanitize(request.form.get("bio",""),300),
                 int(request.form.get("medals_gold",0) or 0),
                 int(request.form.get("medals_silver",0) or 0),
                 int(request.form.get("medals_bronze",0) or 0),
                 int(request.form.get("rating_points",0) or 0),
                 aid))
        audit_log_write("edit_athlete","athlete",aid)
        flash("Sportchi ma'lumotlari yangilandi!", "success")
        return redirect(url_for("admin_athletes"))
    return render_template("admin.html", edit_athlete=ath, page="athletes_edit")

@app.route("/admin/athletes/delete/<int:aid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_athlete(aid):
    db_exec("DELETE FROM athletes WHERE id=?", (aid,))
    audit_log_write("delete_athlete","athlete",aid)
    flash("Sportchi o'chirildi.", "info")
    return redirect(url_for("admin_athletes"))

# ═══════════════════════════════════════════════════════════════
# ADMIN — MENTORS (CRUD + edit)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/mentors")
@admin_required
def admin_mentors():
    mentors = db_query("SELECT * FROM mentors ORDER BY rating DESC")
    return render_template("admin.html", mentors=mentors, page="mentors")

@app.route("/admin/mentors/add", methods=["POST"])
@admin_required
@csrf_protect
def admin_add_mentor():
    fn   = sanitize(request.form.get("full_name",""), 80)
    subj = sanitize(request.form.get("subjects","[]"), 200)
    bio  = sanitize(request.form.get("bio",""), 300)
    exp  = int(request.form.get("experience_years",1) or 1)
    rat  = float(request.form.get("rating",0) or 0)
    price= int(request.form.get("price_per_hour",0) or 0)
    db_exec("INSERT INTO mentors(full_name,subjects,bio,experience_years,rating,price_per_hour) VALUES(?,?,?,?,?,?)",
            (fn, subj, bio, exp, min(rat,5.0), price))
    audit_log_write("add_mentor", details=f"fn={fn}")
    flash(f"'{fn}' mentor qo'shildi!", "success")
    return redirect(url_for("admin_mentors"))

@app.route("/admin/mentors/edit/<int:mid>", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_edit_mentor(mid):
    mentor = db_query("SELECT * FROM mentors WHERE id=?", (mid,), one=True)
    if not mentor: return redirect(url_for("admin_mentors"))
    if request.method == "POST":
        db_exec("""UPDATE mentors SET full_name=?,subjects=?,bio=?,experience_years=?,
                   rating=?,price_per_hour=?,available=? WHERE id=?""",
                (sanitize(request.form.get("full_name",""),80),
                 sanitize(request.form.get("subjects","[]"),200),
                 sanitize(request.form.get("bio",""),300),
                 int(request.form.get("experience_years",1) or 1),
                 min(float(request.form.get("rating",0) or 0), 5.0),
                 int(request.form.get("price_per_hour",0) or 0),
                 1 if request.form.get("available") else 0,
                 mid))
        audit_log_write("edit_mentor","mentor",mid)
        flash("Mentor ma'lumotlari yangilandi!", "success")
        return redirect(url_for("admin_mentors"))
    return render_template("admin.html", edit_mentor=mentor, page="mentors_edit")

@app.route("/admin/mentors/delete/<int:mid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_mentor(mid):
    db_exec("DELETE FROM mentors WHERE id=?", (mid,))
    audit_log_write("delete_mentor","mentor",mid)
    flash("Mentor o'chirildi.", "info")
    return redirect(url_for("admin_mentors"))


# ═══════════════════════════════════════════════════════════════
# ADMIN — TALENTS (CRUD + edit) — yangi: add form
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/talents")
@admin_required
def admin_talents():
    talents = db_query("SELECT * FROM talents ORDER BY score DESC")
    return render_template("admin.html", talents=talents, page="talents")

@app.route("/admin/talents/add", methods=["POST"])
@admin_required
@csrf_protect
def admin_add_talent():
    fn   = sanitize(request.form.get("full_name",""), 80)
    fac  = sanitize(request.form.get("faculty",""), 20)
    sp   = sanitize(request.form.get("specialty",""), 80)
    crs  = int(request.form.get("course",1) or 1)
    cats = request.form.get("categories","[]")
    sc   = int(request.form.get("score",0) or 0)
    bio  = sanitize(request.form.get("bio",""), 300)
    db_exec("INSERT INTO talents(full_name,faculty,specialty,course,categories,score,bio) VALUES(?,?,?,?,?,?,?)",
            (fn, fac, sp, crs, cats, sc, bio))
    audit_log_write("add_talent", details=f"fn={fn}")
    flash(f"'{fn}' iqtidor ro'yxatiga qo'shildi!", "success")
    return redirect(url_for("admin_talents"))

@app.route("/admin/talents/edit/<int:tid>", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_edit_talent(tid):
    talent = db_query("SELECT * FROM talents WHERE id=?", (tid,), one=True)
    if not talent: return redirect(url_for("admin_talents"))
    if request.method == "POST":
        db_exec("UPDATE talents SET full_name=?,faculty=?,specialty=?,course=?,categories=?,score=?,bio=? WHERE id=?",
                (sanitize(request.form.get("full_name",""),80),
                 sanitize(request.form.get("faculty",""),20),
                 sanitize(request.form.get("specialty",""),80),
                 int(request.form.get("course",1) or 1),
                 request.form.get("categories","[]"),
                 int(request.form.get("score",0) or 0),
                 sanitize(request.form.get("bio",""),300),
                 tid))
        audit_log_write("edit_talent","talent",tid)
        flash("Iqtidor ma'lumotlari yangilandi!", "success")
        return redirect(url_for("admin_talents"))
    return render_template("admin.html", edit_talent=talent, page="talents_edit")

@app.route("/admin/talents/delete/<int:tid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_talent(tid):
    db_exec("DELETE FROM talents WHERE id=?", (tid,))
    audit_log_write("delete_talent","talent",tid)
    flash("O'chirildi.", "info")
    return redirect(url_for("admin_talents"))

# ═══════════════════════════════════════════════════════════════
# ADMIN — EVENTS (CRUD + edit + toggle)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/events")
@admin_required
def admin_events():
    evts = db_query("SELECT * FROM events ORDER BY event_date DESC")
    return render_template("admin.html", events=evts, page="events")

@app.route("/admin/events/add", methods=["POST"])
@admin_required
@csrf_protect
def admin_add_event():
    title = sanitize(request.form.get("title",""), 120)
    desc  = sanitize(request.form.get("description",""), 500)
    loc   = sanitize(request.form.get("location",""), 120)
    dt    = sanitize(request.form.get("event_date",""), 20)
    tm    = sanitize(request.form.get("event_time",""), 10)
    cat   = sanitize(request.form.get("category","general"), 20)
    cap   = int(request.form.get("capacity",0) or 0)
    db_exec("INSERT INTO events(title,description,location,event_date,event_time,category,capacity) VALUES(?,?,?,?,?,?,?)",
            (title, desc, loc, dt, tm, cat, cap))
    audit_log_write("add_event", details=f"title={title}")
    flash(f"'{title}' tadbiri qo'shildi!", "success")
    return redirect(url_for("admin_events"))

@app.route("/admin/events/edit/<int:eid>", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_edit_event(eid):
    ev = db_query("SELECT * FROM events WHERE id=?", (eid,), one=True)
    if not ev: return redirect(url_for("admin_events"))
    if request.method == "POST":
        db_exec("""UPDATE events SET title=?,description=?,location=?,event_date=?,
                   event_time=?,category=?,capacity=?,active=? WHERE id=?""",
                (sanitize(request.form.get("title",""),120),
                 sanitize(request.form.get("description",""),500),
                 sanitize(request.form.get("location",""),120),
                 sanitize(request.form.get("event_date",""),20),
                 sanitize(request.form.get("event_time",""),10),
                 sanitize(request.form.get("category","general"),20),
                 int(request.form.get("capacity",0) or 0),
                 1 if request.form.get("active") else 0,
                 eid))
        audit_log_write("edit_event","event",eid)
        flash("Tadbir yangilandi!", "success")
        return redirect(url_for("admin_events"))
    return render_template("admin.html", edit_event=ev, page="events_edit")

@app.route("/admin/events/toggle/<int:eid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_toggle_event(eid):
    ev = db_query("SELECT active,title FROM events WHERE id=?", (eid,), one=True)
    if ev:
        new_v = 0 if ev["active"] else 1
        db_exec("UPDATE events SET active=? WHERE id=?", (new_v, eid))
        audit_log_write("toggle_event","event",eid,f"active={new_v}")
    return redirect(url_for("admin_events"))

@app.route("/admin/events/delete/<int:eid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_event(eid):
    db_exec("DELETE FROM events WHERE id=?", (eid,))
    audit_log_write("delete_event","event",eid)
    flash("Tadbir o'chirildi.", "info")
    return redirect(url_for("admin_events"))


# ═══════════════════════════════════════════════════════════════
# ADMIN — HACKATHONS (CRUD + edit)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/hackathons")
@admin_required
def admin_hackathons():
    hacks = db_query("SELECT * FROM hackathons ORDER BY created_at DESC")
    return render_template("admin.html", hackathons=hacks, page="hackathons")

@app.route("/admin/hackathons/add", methods=["POST"])
@admin_required
@csrf_protect
def admin_add_hackathon():
    title = sanitize(request.form.get("title",""), 120)
    desc  = sanitize(request.form.get("description",""), 500)
    prize = sanitize(request.form.get("prize",""), 100)
    dl    = sanitize(request.form.get("deadline",""), 20)
    stat  = request.form.get("status","upcoming")
    max_p = int(request.form.get("max_participants",0) or 0)
    tech  = sanitize(request.form.get("tech_stack",""), 200)
    org   = sanitize(request.form.get("organizer",""), 80)
    db_exec("INSERT INTO hackathons(title,description,prize,deadline,status,max_participants,tech_stack,organizer) VALUES(?,?,?,?,?,?,?,?)",
            (title, desc, prize, dl, stat, max_p, tech, org))
    audit_log_write("add_hackathon", details=f"title={title}")
    flash(f"'{title}' hackathon qo'shildi!", "success")
    return redirect(url_for("admin_hackathons"))

@app.route("/admin/hackathons/edit/<int:hid>", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_edit_hackathon(hid):
    hack = db_query("SELECT * FROM hackathons WHERE id=?", (hid,), one=True)
    if not hack: return redirect(url_for("admin_hackathons"))
    if request.method == "POST":
        db_exec("""UPDATE hackathons SET title=?,description=?,prize=?,deadline=?,status=?,
                   max_participants=?,tech_stack=?,organizer=? WHERE id=?""",
                (sanitize(request.form.get("title",""),120),
                 sanitize(request.form.get("description",""),500),
                 sanitize(request.form.get("prize",""),100),
                 sanitize(request.form.get("deadline",""),20),
                 request.form.get("status","upcoming"),
                 int(request.form.get("max_participants",0) or 0),
                 sanitize(request.form.get("tech_stack",""),200),
                 sanitize(request.form.get("organizer",""),80),
                 hid))
        audit_log_write("edit_hackathon","hackathon",hid)
        flash("Hackathon yangilandi!", "success")
        return redirect(url_for("admin_hackathons"))
    return render_template("admin.html", edit_hackathon=hack, page="hackathons_edit")

@app.route("/admin/hackathons/delete/<int:hid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_hackathon(hid):
    db_exec("DELETE FROM hackathons WHERE id=?", (hid,))
    audit_log_write("delete_hackathon","hackathon",hid)
    flash("Hackathon o'chirildi.", "info")
    return redirect(url_for("admin_hackathons"))

# ═══════════════════════════════════════════════════════════════
# ADMIN — SESSIONS MANAGEMENT (yangi)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/sessions")
@admin_required
def admin_sessions():
    status_f = sanitize(request.args.get("status",""), 20)
    q = """SELECT s.*,m.full_name as mentor_name,u.full_name as student_name
           FROM sessions s
           LEFT JOIN mentors m ON s.mentor_id=m.id
           LEFT JOIN users u ON s.student_id=u.id
           WHERE 1=1"""
    params = []
    if status_f: q += " AND s.status=?"; params.append(status_f)
    q += " ORDER BY s.created_at DESC"
    sess_list = db_query(q, params)
    counts = {
        "pending":   db_query("SELECT COUNT(*) as n FROM sessions WHERE status='pending'",one=True)["n"],
        "confirmed": db_query("SELECT COUNT(*) as n FROM sessions WHERE status='confirmed'",one=True)["n"],
        "done":      db_query("SELECT COUNT(*) as n FROM sessions WHERE status='done'",one=True)["n"],
        "cancelled": db_query("SELECT COUNT(*) as n FROM sessions WHERE status='cancelled'",one=True)["n"],
    }
    return render_template("admin.html", sessions_list=sess_list,
                           sess_counts=counts, status_filter=status_f, page="sessions")

@app.route("/admin/sessions/update/<int:sid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_update_session(sid):
    new_status = request.form.get("status","pending")
    admin_note = sanitize(request.form.get("admin_note",""), 300)
    db_exec("UPDATE sessions SET status=?,admin_note=? WHERE id=?", (new_status, admin_note, sid))
    audit_log_write("update_session","session",sid,f"status={new_status}")
    flash(f"Sessiya statusi '{new_status}' ga o'zgartirildi.", "success")
    return redirect(url_for("admin_sessions"))

@app.route("/admin/sessions/delete/<int:sid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_session(sid):
    db_exec("DELETE FROM sessions WHERE id=?", (sid,))
    audit_log_write("delete_session","session",sid)
    flash("Sessiya o'chirildi.", "info")
    return redirect(url_for("admin_sessions"))


# ═══════════════════════════════════════════════════════════════
# ADMIN — NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/notifications", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_notifications():
    if request.method == "POST":
        title   = sanitize(request.form.get("title",""), 120)
        body    = sanitize(request.form.get("body",""), 500)
        target  = request.form.get("target","all")
        n_type  = request.form.get("notif_type","info")
        conn    = get_db()
        count   = 0
        try:
            if target == "all":
                users = conn.execute("SELECT id FROM users WHERE role='student'").fetchall()
                for u in users:
                    conn.execute("INSERT INTO notifications(user_id,title,body,notif_type) VALUES(?,?,?,?)",
                                 (u["id"], title, body, n_type))
                    count += 1
            elif target.startswith("faculty:"):
                fac = target.split(":",1)[1]
                users = conn.execute("SELECT id FROM users WHERE role='student' AND faculty=?", (fac,)).fetchall()
                for u in users:
                    conn.execute("INSERT INTO notifications(user_id,title,body,notif_type) VALUES(?,?,?,?)",
                                 (u["id"], title, body, n_type))
                    count += 1
            elif target.startswith("user:"):
                uid = int(target.split(":",1)[1])
                conn.execute("INSERT INTO notifications(user_id,title,body,notif_type) VALUES(?,?,?,?)",
                             (uid, title, body, n_type))
                count = 1
            conn.commit()
        finally:
            conn.close()
        audit_log_write("send_notification", details=f"target={target} count={count}")
        flash(f"Bildirishnoma {count} foydalanuvchiga yuborildi.", "success")
        return redirect(url_for("admin_notifications"))
    notifs  = db_query("SELECT n.*,u.full_name FROM notifications n LEFT JOIN users u ON n.user_id=u.id ORDER BY n.created_at DESC LIMIT 50")
    faculties = db_query("SELECT DISTINCT faculty FROM users WHERE role='student' AND faculty!='' ORDER BY faculty")
    return render_template("admin.html", notifs=notifs, faculties=faculties, page="notifications")

@app.route("/admin/notifications/delete/<int:nid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_notif(nid):
    db_exec("DELETE FROM notifications WHERE id=?", (nid,))
    return redirect(url_for("admin_notifications"))

# ═══════════════════════════════════════════════════════════════
# ADMIN — ANNOUNCEMENTS (yangi)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/announcements", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_announcements():
    if request.method == "POST":
        title   = sanitize(request.form.get("title",""), 120)
        body    = sanitize(request.form.get("body",""), 800)
        a_type  = request.form.get("type","info")
        pinned  = 1 if request.form.get("pinned") else 0
        expires = sanitize(request.form.get("expires_at",""), 20)
        db_exec("INSERT INTO announcements(title,body,type,pinned,expires_at,created_by) VALUES(?,?,?,?,?,?)",
                (title, body, a_type, pinned, expires, session.get("user_id",0)))
        audit_log_write("add_announcement", details=f"title={title}")
        flash(f"E'lon qo'shildi: '{title}'", "success")
        return redirect(url_for("admin_announcements"))
    anns = db_query("SELECT a.*,u.full_name as author FROM announcements a LEFT JOIN users u ON a.created_by=u.id ORDER BY a.pinned DESC,a.created_at DESC")
    return render_template("admin.html", announcements=anns, page="announcements")

@app.route("/admin/announcements/toggle/<int:aid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_toggle_ann(aid):
    ann = db_query("SELECT active FROM announcements WHERE id=?", (aid,), one=True)
    if ann:
        db_exec("UPDATE announcements SET active=? WHERE id=?", (0 if ann["active"] else 1, aid))
    return redirect(url_for("admin_announcements"))

@app.route("/admin/announcements/delete/<int:aid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_ann(aid):
    db_exec("DELETE FROM announcements WHERE id=?", (aid,))
    flash("E'lon o'chirildi.", "info")
    return redirect(url_for("admin_announcements"))


# ═══════════════════════════════════════════════════════════════
# ADMIN — AUDIT LOG (yangi)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/audit")
@admin_required
def admin_audit():
    action_f = sanitize(request.args.get("action",""), 50)
    user_f   = sanitize(request.args.get("user",""), 50)
    page_n   = int(request.args.get("p",1) or 1)
    per = 30; offset = (page_n-1)*per
    q = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    if action_f: q += " AND action LIKE ?"; params.append(f"%{action_f}%")
    if user_f:   q += " AND username LIKE ?"; params.append(f"%{user_f}%")
    q += f" ORDER BY created_at DESC LIMIT {per} OFFSET {offset}"
    logs = db_query(q, params)
    total = db_query("SELECT COUNT(*) as n FROM audit_log",one=True)["n"]
    return render_template("admin.html", audit_logs=logs, action_filter=action_f,
                           user_filter=user_f, page_num=page_n, total=total, per=per, page="audit")

@app.route("/admin/audit/clear", methods=["POST"])
@admin_required
@csrf_protect
def admin_clear_audit():
    db_exec("DELETE FROM audit_log WHERE created_at < date('now','-30 days')")
    audit_log_write("clear_audit")
    flash("30 kundan eski yozuvlar o'chirildi.", "info")
    return redirect(url_for("admin_audit"))

@app.route("/admin/audit/export")
@admin_required
def admin_export_audit():
    logs = db_query("SELECT id,username,action,target_type,target_id,details,ip_address,created_at FROM audit_log ORDER BY created_at DESC")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID","Foydalanuvchi","Amal","Tur","ID","Tafsilot","IP","Vaqt"])
    for l in logs:
        writer.writerow([l["id"],l["username"],l["action"],l["target_type"],
                         l["target_id"],l["details"],l["ip_address"],l["created_at"]])
    output.seek(0)
    return make_response(output.getvalue(), 200,
                         {"Content-Type":"text/csv; charset=utf-8",
                          "Content-Disposition":"attachment; filename=audit_log.csv"})

# ═══════════════════════════════════════════════════════════════
# ADMIN — LOGIN HISTORY (yangi)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/login-history")
@admin_required
def admin_login_history():
    page_n = int(request.args.get("p",1) or 1)
    per = 30; offset = (page_n-1)*per
    logs   = db_query(f"SELECT * FROM login_attempts ORDER BY created_at DESC LIMIT {per} OFFSET {offset}")
    total  = db_query("SELECT COUNT(*) as n FROM login_attempts",one=True)["n"]
    failed = db_query("SELECT COUNT(*) as n FROM login_attempts WHERE success=0",one=True)["n"]
    return render_template("admin.html", login_logs=logs, total=total, failed=failed,
                           page_num=page_n, per=per, page="login_history")

@app.route("/admin/login-history/clear", methods=["POST"])
@admin_required
@csrf_protect
def admin_clear_login_history():
    db_exec("DELETE FROM login_attempts WHERE created_at < date('now','-14 days')")
    flash("14 kundan eski login tarixi o'chirildi.", "info")
    return redirect(url_for("admin_login_history"))

# ═══════════════════════════════════════════════════════════════
# ADMIN — SYSTEM HEALTH (yangi)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/system")
@admin_required
def admin_system():
    import os as _os
    db_size = _os.path.getsize(DB_PATH) if _os.path.exists(DB_PATH) else 0
    uploads_size = sum(
        _os.path.getsize(_os.path.join(r, f))
        for r, _, files in _os.walk(UPLOAD_FOLDER) for f in files
    ) if _os.path.exists(UPLOAD_FOLDER) else 0
    # Blocked IPs
    blocked = db_query("SELECT * FROM rate_limits WHERE blocked_until > datetime('now') ORDER BY blocked_until DESC")
    # Failed logins last 24h
    failed_24h = db_query("SELECT COUNT(*) as n FROM login_attempts WHERE success=0 AND created_at > datetime('now','-1 day')",one=True)["n"]
    # Active sessions count
    active_count = db_query("SELECT COUNT(*) as n FROM sessions WHERE status='pending'",one=True)["n"]
    settings_all = {r["key"]:r["value"] for r in db_query("SELECT * FROM settings")}
    return render_template("admin.html",
        db_size=db_size, uploads_size=uploads_size,
        blocked_ips=blocked, failed_24h=failed_24h,
        active_sessions=active_count, sys_settings=settings_all,
        page="system")

@app.route("/admin/system/unblock/<int:rid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_unblock_ip(rid):
    db_exec("UPDATE rate_limits SET blocked_until='' WHERE id=?", (rid,))
    audit_log_write("unblock_ip","rate_limit",rid)
    flash("IP bloki olib tashlandi.", "success")
    return redirect(url_for("admin_system"))

# ═══════════════════════════════════════════════════════════════
# ADMIN — STATISTICS / GRAFIK (yangi)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/statistics")
@admin_required
def admin_statistics():
    # Oylik registratsiya
    monthly_reg = db_query("""SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as cnt
                               FROM users WHERE role='student' GROUP BY month ORDER BY month DESC LIMIT 12""")
    # Fakultet bo'yicha
    by_faculty  = db_query("""SELECT faculty, COUNT(*) as cnt FROM users
                               WHERE role='student' AND faculty!='' GROUP BY faculty ORDER BY cnt DESC""")
    # Sport bo'yicha
    by_sport    = db_query("SELECT sport, COUNT(*) as cnt FROM athletes GROUP BY sport ORDER BY cnt DESC LIMIT 10")
    # Sessiya holati
    sess_status = db_query("SELECT status, COUNT(*) as cnt FROM sessions GROUP BY status")
    # Talant kategoriya
    talents_cat = db_query("SELECT categories, COUNT(*) as cnt FROM talents GROUP BY categories ORDER BY cnt DESC LIMIT 8")
    # Login statistika
    login_stats = db_query("""SELECT date(created_at) as day, SUM(success) as ok, COUNT(*)-SUM(success) as fail
                               FROM login_attempts GROUP BY day ORDER BY day DESC LIMIT 14""")
    return render_template("admin.html",
        monthly_reg=monthly_reg, by_faculty=by_faculty,
        by_sport=by_sport, sess_status=sess_status,
        talents_cat=talents_cat, login_stats=login_stats,
        page="statistics")


# ═══════════════════════════════════════════════════════════════
# ADMIN — MEDIA UPLOAD (yangi)
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/media", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_media():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Fayl tanlanmadi.", "danger")
            return redirect(url_for("admin_media"))
        if not allowed_file(f.filename):
            flash("Ruxsat etilmagan fayl turi! Faqat: png, jpg, jpeg, gif, webp", "danger")
            return redirect(url_for("admin_media"))
        import os as _os, uuid as _uuid
        ext = f.filename.rsplit(".", 1)[1].lower()
        unique_name = f"{_uuid.uuid4().hex}.{ext}"
        save_path = _os.path.join(UPLOAD_FOLDER, unique_name)
        f.save(save_path)
        size = _os.path.getsize(save_path)
        db_exec("INSERT INTO media(filename,original_name,file_type,file_size,uploaded_by) VALUES(?,?,?,?,?)",
                (unique_name, f.filename[:200], "image", size, session.get("user_id",0)))
        audit_log_write("upload_media", details=f"file={unique_name}")
        flash(f"Fayl yuklandi: {f.filename}", "success")
        return redirect(url_for("admin_media"))
    media_files = db_query("SELECT m.*,u.full_name as uploader FROM media m LEFT JOIN users u ON m.uploaded_by=u.id ORDER BY m.created_at DESC")
    return render_template("admin.html", media_files=media_files, page="media")

@app.route("/admin/media/delete/<int:mid>", methods=["POST"])
@admin_required
@csrf_protect
def admin_delete_media(mid):
    m = db_query("SELECT filename FROM media WHERE id=?", (mid,), one=True)
    if m:
        import os as _os
        fpath = _os.path.join(UPLOAD_FOLDER, m["filename"])
        if _os.path.exists(fpath):
            _os.remove(fpath)
        db_exec("DELETE FROM media WHERE id=?", (mid,))
        audit_log_write("delete_media","media",mid)
        flash("Fayl o'chirildi.", "info")
    return redirect(url_for("admin_media"))

# ═══════════════════════════════════════════════════════════════
# ADMIN — SETTINGS
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/settings", methods=["GET","POST"])
@admin_required
@csrf_protect
def admin_settings():
    if request.method == "POST":
        keys = ["site_name","university","registration_open","maintenance",
                "maintenance_msg","allowed_admin_ips","max_login_attempts",
                "lockout_minutes","session_lifetime","contact_email","contact_phone"]
        conn = get_db()
        try:
            for k in keys:
                v = sanitize(request.form.get(k,""), 300)
                conn.execute("INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES(?,?,datetime('now'))", (k, v))
            conn.commit()
        finally:
            conn.close()
        audit_log_write("update_settings")
        flash("Sozlamalar saqlandi!", "success")
        return redirect(url_for("admin_settings"))
    settings_all = db_query("SELECT * FROM settings ORDER BY key")
    return render_template("admin.html",
                           settings={r["key"]:r["value"] for r in settings_all},
                           page="settings")

# ═══════════════════════════════════════════════════════════════
# ADMIN — CHANGE OWN PASSWORD
# ═══════════════════════════════════════════════════════════════
@app.route("/admin/change-password", methods=["POST"])
@admin_required
@csrf_protect
def admin_change_password():
    old_pw  = request.form.get("old_password","")
    new_pw  = request.form.get("new_password","")
    conf_pw = request.form.get("confirm_password","")
    user = db_query("SELECT * FROM users WHERE id=?", (session.get("user_id"),), one=True)
    salt = user["password_salt"] or ""
    if not verify_password(old_pw, user["password"], salt) and _hash(old_pw) != user["password"]:
        flash("Eski parol noto'g'ri!", "danger")
        return redirect(url_for("admin_settings"))
    if new_pw != conf_pw:
        flash("Yangi parollar mos emas!", "danger")
        return redirect(url_for("admin_settings"))
    if len(new_pw) < 6:
        flash("Yangi parol kamida 6 belgi bo'lishi kerak!", "danger")
        return redirect(url_for("admin_settings"))
    new_h, new_s = _hash_password(new_pw)
    db_exec("UPDATE users SET password=?,password_salt=? WHERE id=?",
            (new_h, new_s, session.get("user_id")))
    audit_log_write("admin_change_password","user",session.get("user_id"))
    flash("Admin paroli muvaffaqiyatli o'zgartirildi!", "success")
    return redirect(url_for("admin_settings"))


# ═══════════════════════════════════════════════════════════════
# API (JSON) — himoyalangan + yangilangan
# ═══════════════════════════════════════════════════════════════
@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

@app.route("/api/athletes")
def api_athletes():
    athletes = db_query("SELECT id,full_name,sport,faculty,course,level,rating_points,medals_gold,medals_silver,medals_bronze FROM athletes ORDER BY rating_points DESC")
    return jsonify([dict(a) for a in athletes])

@app.route("/api/talents")
def api_talents():
    talents = db_query("SELECT id,full_name,faculty,specialty,course,categories,score FROM talents ORDER BY score DESC")
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

@app.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    """Admin uchun real-vaqt statistika"""
    stats = get_stats()
    stats["pending_sessions"] = db_query("SELECT COUNT(*) as n FROM sessions WHERE status='pending'",one=True)["n"]
    stats["failed_logins_24h"] = db_query("SELECT COUNT(*) as n FROM login_attempts WHERE success=0 AND created_at>datetime('now','-1 day')",one=True)["n"]
    stats["blocked_ips"] = db_query("SELECT COUNT(*) as n FROM rate_limits WHERE blocked_until>datetime('now')",one=True)["n"]
    stats["unread_total"] = db_query("SELECT COUNT(*) as n FROM notifications WHERE read=0",one=True)["n"]
    return jsonify(stats)

@app.route("/api/admin/chart-data")
@admin_required
def api_chart_data():
    monthly = db_query("""SELECT strftime('%m',created_at) as mo, COUNT(*) as cnt
                          FROM users WHERE role='student' AND created_at>=date('now','-12 months')
                          GROUP BY mo ORDER BY mo""")
    by_fac  = db_query("SELECT faculty,COUNT(*) as cnt FROM users WHERE role='student' AND faculty!='' GROUP BY faculty ORDER BY cnt DESC LIMIT 6")
    by_sport= db_query("SELECT sport,COUNT(*) as cnt FROM athletes GROUP BY sport ORDER BY cnt DESC LIMIT 8")
    return jsonify({
        "monthly": [{"month": r["mo"], "count": r["cnt"]} for r in monthly],
        "by_faculty": [{"name": r["faculty"], "count": r["cnt"]} for r in by_fac],
        "by_sport": [{"name": r["sport"], "count": r["cnt"]} for r in by_sport],
    })


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 58)
    print("  🎓  SAMdu / S_TATU Platform  v2.0")
    print("=" * 58)
    print(f"  🌐  URL    : http://localhost:5000")
    print(f"  🔐  Admin  : http://localhost:5000/admin")
    print(f"  👤  Login  : admin / admin123")
    print(f"  🛡  CSRF   : Yoqilgan")
    print(f"  🔒  Rate   : Yoqilgan")
    print(f"  📝  Audit  : Yoqilgan")
    print("=" * 58)
    init_db()
    print("  ✅  Tayyor!\n")
    import threading, webbrowser, time
    def open_browser():
        time.sleep(1.2)
        webbrowser.open("http://localhost:5000")
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
