from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo  # Python 3.9+
from db import engine, SessionLocal
from models import Base, User
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv
from models import Flag
import json
import random, hashlib
import os
import secrets
import re
from models import Flag


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))

# Create DB tables if they don't exist
Base.metadata.create_all(bind=engine)

load_dotenv()  # reads .env into os.environ

PARIS = ZoneInfo("Europe/Paris")

# Harden session cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True         # JS cannot read session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"        # limit cross-site sends (mitigate CSRF)

# Only enable this when your site is served over HTTPS (production)
if os.environ.get("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True       # cookie only sent over HTTPS

# Absolute max session age (cookie expiry)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)

# Inactivity timeout (custom)
INACTIVITY_TIMEOUT = timedelta(minutes=30)

# --- Paths and constants ---
QUESTION_FILE = "set_ok_cleaned.json"
USER_DIR = "users"

# --- Utility functions ---
def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("home"))
        return view_func(*args, **kwargs)
    return wrapped

def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def get_known_users():
    if not os.path.exists(USER_DIR):
        return []
    return [filename.replace(".json", "") for filename in os.listdir(USER_DIR) if filename.endswith(".json")]

def email_to_id(email: str) -> str:
    base = email.strip().lower()
    return re.sub(r'[^a-z0-9]+', '_', base).strip('_')

def email_exists_json(email: str) -> bool:
    """Return True if a user JSON already uses this email (case-insensitive)."""
    normalized = email.strip().lower()
    if not os.path.isdir(USER_DIR):
        return False
    for fname in os.listdir(USER_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(USER_DIR, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if str(data.get("email", "")).strip().lower() == normalized:
                return True
        except Exception:
            # ignore unreadable/corrupt files
            continue
    return False

def get_user_by_email_db(email: str):
    """Fetch a user row from the DB by normalized email, or None if not found."""
    normalized = email.strip().lower()
    with SessionLocal() as db:
        return db.query(User).filter(User.email == normalized).first()

def sync_user_to_db_from_json(user_data: dict):
    """Push the updated JSON stats into the DB row for this user (by email)."""
    email = (user_data.get("email") or "").strip().lower()
    if not email:
        return
    try:
        with SessionLocal() as db:
            u = db.query(User).filter(User.email == email).first()
            if not u:
                return

            # Core aggregates
            u.score = int(user_data.get("score", 0))
            u.current_streak = int(user_data.get("current_streak", 0))
            u.best_streak = int(user_data.get("best_streak", 0))
            u.total_answered = int(user_data.get("total_answered", 0))
            u.total_correct = int(user_data.get("total_correct", 0))
            u.total_wrong = int(user_data.get("total_wrong", 0))
            u.success_rate_overall = float(user_data.get("success_rate_overall", 0.0))
            u.time_spent_minutes = int(user_data.get("time_spent_minutes", 0))

            # Structured aggregates
            u.daily_stats = user_data.get("daily_stats", {}) or {}
            u.monthly_stats = user_data.get("monthly_stats", {}) or {}
            u.theme_stats = user_data.get("theme_stats", {}) or {}
            u.best_theme = user_data.get("best_theme")
            u.worst_theme = user_data.get("worst_theme")
            u.incorrect_questions = user_data.get("incorrect_questions", []) or []

            # Streak object
            u.login_streak = user_data.get("login_streak", {}) or {}

            # Plan flags (keep existing if missing)
            if "plan" in user_data:
                u.plan = user_data["plan"] or u.plan
            if "free_forever" in user_data:
                u.free_forever = bool(user_data["free_forever"])
            if "quota_used" in user_data:
                u.quota_used = int(user_data["quota_used"])

            db.commit()
    except Exception:
        # Don't crash the request if the sync fails; JSON remains source-of-truth for now
        pass

def _pool_key(mode: str, theme: str | None) -> str:
    return f"{mode}" if not theme else f"{mode}:{theme}"

def _pool_version(eligible_ids: list) -> str:
    h = hashlib.sha256(",".join(map(str, sorted(eligible_ids))).encode("utf-8")).hexdigest()
    return h[:12]

def pick_next_in_cycle(user_data: dict, eligible_ids: list, mode: str, theme: str | None = None):
    """
    Returns the next question id without repeats until all are seen, then reshuffles.
    Persists state in user_data["question_rotation"].
    """
    if not eligible_ids:
        return None
    rotation = user_data.setdefault("question_rotation", {})
    key = _pool_key(mode, theme)
    ver = _pool_version(eligible_ids)
    pool = rotation.get(key)

    eligible_set = set(eligible_ids)
    if not pool or pool.get("version") != ver:
        remaining = list(eligible_ids)
        random.shuffle(remaining)
        rotation[key] = pool = {"version": ver, "remaining": remaining}
    else:
        pool["remaining"] = [qid for qid in pool.get("remaining", []) if qid in eligible_set]

    if not pool["remaining"]:
        new_cycle = list(eligible_ids)
        random.shuffle(new_cycle)
        pool["remaining"] = new_cycle

    return pool["remaining"].pop()

# --- Question Logic ---
with open(QUESTION_FILE, "r", encoding="utf-8") as f:
    questions = json.load(f)

def get_random_question():
    """Returns one random question from the list."""
    return random.choice(questions)

def update_login_streak(user_data):
    """
    Increments the daily login streak for 'today' in Europe/Paris.
    Call this ONLY when the user has actually played at least one question today.
    """
    today = datetime.now(PARIS).date()
    yesterday = today - timedelta(days=1)

    streak = user_data.get("login_streak", {"last_date": None, "count": 0, "best": 0})
    last_date_str = streak.get("last_date")
    last_date = datetime.strptime(last_date_str, "%Y-%m-%d").date() if last_date_str else None

    if last_date == today:
        # already counted today
        pass
    elif last_date == yesterday:
        streak["count"] += 1
    else:
        streak["count"] = 1

    streak["best"] = max(streak.get("best", 0), streak["count"])
    streak["last_date"] = today.isoformat()
    user_data["login_streak"] = streak


# --- Home page ---
@app.route("/login-email", methods=["POST"])
def login_email():
    from werkzeug.security import check_password_hash

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return render_template("home.html", error="Please enter your email and password."), 400

    # ----- DB auth (verify password from database) -----
    db_row = get_user_by_email_db(email)
    if not db_row:
        return render_template("home.html", error="No account found with this email."), 400

    if not check_password_hash(db_row.password_hash, password):
        return render_template("home.html", error="Incorrect password."), 400

    # Consistent filename key from email (matches your existing JSON filenames)
    def email_to_key(e: str) -> str:
        return e.replace("@", "_").replace(".", "_")

    user_key = email_to_key(email)
    user_file = os.path.join(USER_DIR, f"{user_key}.json")

    # ----- Load (or create) the JSON profile -----
    if os.path.exists(user_file):
        with open(user_file, "r", encoding="utf-8") as f:
            user_data = json.load(f)
    else:
        # If the JSON is missing, bootstrap it from the DB row so the rest of your app keeps working
        user_data = {
            "email": db_row.email,
            "name": db_row.name or db_row.avatar_name or "user",
            "avatar_name": db_row.avatar_name,
            "avatar": db_row.avatar,
            "password_hash": db_row.password_hash,
            "secret_question": db_row.secret_question,
            "secret_answer_hash": db_row.secret_answer_hash,
            "created_at": (db_row.created_at or datetime.utcnow()).strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": None,
            "score": db_row.score or 0,
            "current_streak": db_row.current_streak or 0,
            "best_streak": db_row.best_streak or 0,
            "total_answered": db_row.total_answered or 0,
            "total_correct": db_row.total_correct or 0,
            "total_wrong": db_row.total_wrong or 0,
            "success_rate_overall": float(db_row.success_rate_overall or 0.0),
            "time_spent_minutes": db_row.time_spent_minutes or 0,
            "daily_stats": db_row.daily_stats or {},
            "monthly_stats": db_row.monthly_stats or {},
            "theme_stats": db_row.theme_stats or {},
            "best_theme": db_row.best_theme,
            "worst_theme": db_row.worst_theme,
            "incorrect_questions": db_row.incorrect_questions or [],
            "login_streak": db_row.login_streak or {},
            "free_forever": bool(db_row.free_forever),
            "plan": db_row.plan or "free",
            "quota_used": db_row.quota_used or 0,
        }

    # ----- Set session (unchanged logic) -----
    session["user"] = user_key
    session.permanent = True
    session["last_seen"] = datetime.now(timezone.utc).isoformat()

    # We DO NOT update the login streak here anymore.
    # It increments only on the first answered question of the day in /submit-answer.

    # Update last_login in JSON
    now_utc = datetime.now(timezone.utc)
    user_data["last_login"] = now_utc.strftime("%Y-%m-%d %H:%M:%S")
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

    # Also update last_login in DB (UTC)
    with SessionLocal() as db:
        u = db.query(User).filter(User.email == email).first()
        if u:
            u.last_login = datetime.utcnow()
            db.commit()

    return redirect(url_for("profile"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        # prefill email if we came from /login-email
        email = request.args.get("email", "")
        avatar_dir = os.path.join("static", "avatars")
        avatars = [f for f in os.listdir(avatar_dir) if f.lower().endswith(".png")]
        avatars.sort()
        return render_template("register.html", email=email, avatars=avatars)

    # POST: create the user in DB + JSON
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "").strip()
    avatar_name = request.form.get("avatar_name", "").strip() or email.split("@")[0]
    secret_question = request.form.get("secret_question", "").strip()
    secret_answer = request.form.get("secret_answer", "").strip()
    avatar = request.form.get("avatar", "").strip()

    # Basic validation
    if not all([email, password, avatar_name, secret_question, secret_answer, avatar]):
        avatar_dir = os.path.join("static", "avatars")
        avatars = [f for f in os.listdir(avatar_dir) if f.lower().endswith(".png")]
        avatars.sort()
        return render_template("register.html", email=email, avatars=avatars,
                               error="Merci de compléter tous les champs."), 400

    # Hashes (use scrypt for consistency with your login path)
    password_hash = generate_password_hash(password, method="scrypt")
    secret_answer_hash = hash_text(secret_answer)

    # Duplicate guard — JSON (legacy)
    if email_exists_json(email):
        avatar_dir = os.path.join("static", "avatars")
        avatars = [f for f in os.listdir(avatar_dir) if f.lower().endswith(".png")]
        avatars.sort()
        return render_template("register.html", email=email, avatars=avatars,
                               error="This email is already registered. Please log in or reset your password."), 400

    # Duplicate guard — DB (authoritative)
    with SessionLocal() as db:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            avatar_dir = os.path.join("static", "avatars")
            avatars = [f for f in os.listdir(avatar_dir) if f.lower().endswith(".png")]
            avatars.sort()
            return render_template("register.html", email=email, avatars=avatars,
                                   error="This email is already registered. Please log in or reset your password."), 400

        # Create in DB
        new_user = User(
            email=email,
            name=avatar_name,
            avatar_name=avatar_name,
            avatar=avatar,
            password_hash=password_hash,
            secret_question=secret_question,
            secret_answer_hash=secret_answer_hash,

            # Defaults matching your JSON structure
            daily_stats={},
            monthly_stats={},
            theme_stats={},
            incorrect_questions=[],
            login_streak={"last_date": None, "count": 0, "best": 0},
            plan="free",
            free_forever=False,
            quota_used=0,
        )
        db.add(new_user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            avatar_dir = os.path.join("static", "avatars")
            avatars = [f for f in os.listdir(avatar_dir) if f.lower().endswith(".png")]
            avatars.sort()
            return render_template("register.html", email=email, avatars=avatars,
                                   error="This email is already registered. Please log in or reset your password."), 400

    # Create JSON profile (legacy path stays intact)
    name = email_to_id(email)  # uses your existing helper to build filename key
    user_file = os.path.join(USER_DIR, f"{name}.json")
    os.makedirs(USER_DIR, exist_ok=True)

    now_utc_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    user_data = {
        "email": email,
        "name": avatar_name,
        "avatar_name": avatar_name,
        "avatar": avatar,
        "password_hash": password_hash,
        "secret_question": secret_question,
        "secret_answer_hash": secret_answer_hash,
        "created_at": now_utc_str,
        "last_login": now_utc_str,

        "score": 0,
        "current_streak": 0,
        "best_streak": 0,
        "total_answered": 0,
        "total_correct": 0,
        "total_wrong": 0,
        "success_rate_overall": 0.0,
        "time_spent_minutes": 0,
        "daily_stats": {},
        "monthly_stats": {},
        "theme_stats": {},
        "best_theme": None,
        "worst_theme": None,
        "incorrect_questions": [],

        # Start at zero; increment only after first answered question of the day
        "login_streak": {"last_date": None, "count": 0, "best": 0},

        "free_forever": False,
        "plan": "free",
        "quota_used": 0
    }

    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

    # Log the user in (unchanged)
    session["user"] = name
    session.permanent = True
    session["last_seen"] = datetime.now(timezone.utc).isoformat()
    return redirect(url_for("profile"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "GET":
        return render_template("forgot.html")

    # POST
    email = request.form.get("email", "").strip().lower()
    if not email:
        return render_template("forgot.html", error="Merci d’entrer votre e‑mail.")

    name = email_to_id(email)
    user_file = os.path.join(USER_DIR, f"{name}.json")
    if not os.path.exists(user_file):
        return render_template("forgot.html", error="Aucun compte associé à cet e‑mail.")

    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    # Show the question and pass the email forward
    secret_question = user_data.get("secret_question", "")
    return render_template("reset.html", email=email, secret_question=secret_question)

@app.route("/reset", methods=["POST"])
def reset():
    email = request.form.get("email", "").strip().lower()
    answer = request.form.get("secret_answer", "").strip()
    new_password = request.form.get("new_password", "").strip()

    if not all([email, answer, new_password]):
        return render_template("reset.html", email=email, secret_question=request.form.get("secret_question", ""), error="Merci de remplir tous les champs.")

    name = email_to_id(email)
    user_file = os.path.join(USER_DIR, f"{name}.json")
    if not os.path.exists(user_file):
        # Unlikely (user deleted), send back to forgot
        return redirect(url_for("forgot"))

    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    # Check secret answer
    expected = user_data.get("secret_answer_hash")
    if expected != hash_text(answer):
        return render_template("reset.html", email=email, secret_question=user_data.get("secret_question", ""), error="Réponse incorrecte.")

    # Update password
    user_data["password_hash"] = generate_password_hash(new_password)
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

    # Optionally: log them in automatically
    session["user"] = email_to_id(email)
    session.permanent = True
    session["last_seen"] = datetime.now(timezone.utc).isoformat()
    return redirect(url_for("profile"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.before_request
def enforce_session_timeouts():
    # Always mark sessions as permanent so the cookie gets an expiry
    session.permanent = True

    # If user is not logged in, nothing to do
    if "user" not in session:
        return

    now = datetime.now(timezone.utc)
    last_seen_str = session.get("last_seen")

    if last_seen_str:
        try:
            last_seen = datetime.fromisoformat(last_seen_str)
            # If stored value is naive (shouldn't be), assume UTC
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
        except ValueError:
            last_seen = now  # don't kick them out immediately if parsing fails

        # Inactivity timeout
        if (now - last_seen) > INACTIVITY_TIMEOUT:
            session.clear()  # drop the session
            # No redirect here; @login_required will send them to / on protected routes
            return

    # Update last activity for sliding timeout
    session["last_seen"] = now.isoformat()


@app.route("/", methods=["GET"])
def home():
    known_users = get_known_users()

    if "user" in session:
        user_file = os.path.join(USER_DIR, f"{session['user']}.json")
        if os.path.exists(user_file):
            with open(user_file, "r", encoding="utf-8") as f:
                user_data = json.load(f)

            # ✅ Login streak logic
            today = datetime.now().date()
            yesterday = today - timedelta(days=1)

            streak = user_data.get("login_streak", {
                "last_date": None,
                "count": 0,
                "best": 0
            })

            last_date_str = streak.get("last_date")
            last_date = datetime.strptime(last_date_str, "%Y-%m-%d").date() if last_date_str else None

            if last_date == today:
                pass  # Already counted today
            elif last_date == yesterday:
                streak["count"] += 1
            else:
                streak["count"] = 1

            streak["best"] = max(streak.get("best", 0), streak["count"])
            streak["last_date"] = today.isoformat()
            user_data["login_streak"] = streak

            # ✅ Finalize Codestan session
            finalize_active_session(user_data)

            with open(user_file, "w", encoding="utf-8") as f:
                json.dump(user_data, f, indent=2, ensure_ascii=False)

    top_users = []

    for username in get_known_users():
        path = os.path.join(USER_DIR, f"{username}.json")
        if not os.path.exists(path):
            continue

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        top_users.append({
            "name": data["name"],
            "avatar": data.get("avatar", "default.png"),
            "score": data.get("score", 0),
            "best_streak": data.get("best_streak", 0),
            "login_streak": data.get("login_streak", {}).get("best", 0)
        })

    # Get top 1 for each category
    top_score = max(top_users, key=lambda u: u["score"], default=None)
    top_streak = max(top_users, key=lambda u: u["best_streak"], default=None)
    top_login = max(top_users, key=lambda u: u["login_streak"], default=None)

    return render_template(
        "home.html",
        known_users=known_users,
        top_score=top_score,
        top_streak=top_streak,
        top_login=top_login
    )


# --- Check name: existing or new user ---
@app.route("/check-user", methods=["POST"])
def check_user():
    name = request.form.get("name", "").strip().lower()
    password = request.form.get("password", "").strip()
    user_file = os.path.join(USER_DIR, f"{name}.json")

    if not name:
        return render_template("home.html", known_users=get_known_users(), error="Veuillez entrer votre nom.")

    # ✅ Existing user
    if os.path.exists(user_file):
        if password:
            # ✅ Password was submitted → validate and go to profile
            with open(user_file, "r", encoding="utf-8") as f:
                user_data = json.load(f)

            if user_data["password_hash"] != hash_text(password):
                return render_template("home.html", known_users=get_known_users(), error="Mot de passe incorrect.")

            session["user"] = name
            return redirect(url_for("profile"))
        else:
            # ❌ Password missing → fallback to login page (not ideal anymore)
            return render_template("login.html", name=name)

    # ✅ New user → go to registration
    avatar_dir = os.path.join("static", "avatars")
    avatars = [f for f in os.listdir(avatar_dir) if f.lower().endswith(".png")]
    avatars.sort()

    return render_template("register.html", name=name, avatars=avatars)

# --- Login (handles both existing user & profile creation) ---
@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("name", "").strip().lower()
    password = request.form.get("password", "").strip()
    user_file = os.path.join(USER_DIR, f"{name}.json")
    is_new_user = not os.path.exists(user_file)

    if is_new_user:
        email = request.form.get("email", "").strip()
        secret_question = request.form.get("secret_question", "").strip()
        secret_answer = request.form.get("secret_answer", "").strip()
        avatar = request.form.get("avatar", "").strip()

        if not all([email, secret_question, secret_answer, avatar]):
            return render_template("home.html", known_users=get_known_users(), error="Merci de remplir tous les champs pour créer un profil.")

        user_data = {
            "name": name,
            "email": email,
            "avatar": avatar,
            "password_hash": hash_text(password),
            "secret_question": secret_question,
            "secret_answer_hash": hash_text(secret_answer),
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "score": 0,
            "current_streak": 0,
            "best_streak": 0,
            "total_answered": 0,
            "total_correct": 0,
            "total_wrong": 0,
            "success_rate_overall": 0.0,
            "time_spent_minutes": 0,
            "daily_stats": {},
            "monthly_stats": {},
            "theme_stats": {},
            "best_theme": None,
            "worst_theme": None,
            "incorrect_questions": [],
            "login_streak": {
                "last_date": datetime.now().date().isoformat(),
                "count": 1,
                "best": 1
            }

        }

        os.makedirs(USER_DIR, exist_ok=True)
        with open(user_file, "w", encoding="utf-8") as f:
            json.dump(user_data, f, indent=2, ensure_ascii=False)

        session["user"] = name
        return redirect(url_for("profile"))

    # Existing user: verify password
    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    if user_data["password_hash"] != hash_text(password):
        return render_template("login.html", name=name, error="Mot de passe incorrect.")

    # Update last login time
    user_data["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

    session["user"] = name
    return redirect(url_for("profile"))

# --- Placeholder Profile Page ---
@app.route("/profile")
@login_required
def profile():
    if "user" not in session:
        return redirect(url_for("home"))

    user_file = os.path.join(USER_DIR, f"{session['user']}.json")
    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    # Finalize active session before showing page
    finalize_active_session(user_data)

    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

    avatar_dir = os.path.join("static", "avatars")
    avatars = [f for f in os.listdir(avatar_dir) if f.lower().endswith(".png")]
    avatars.sort()

    return render_template("profile.html", user_data=user_data, avatars=avatars)

@app.route("/stats")
@login_required
def stats():
    if "user" not in session:
        return redirect(url_for("home"))

    user_file = os.path.join(USER_DIR, f"{session['user']}.json")
    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    return render_template("stats.html", user_data=user_data)

@app.route("/update-avatar", methods=["POST"])
@login_required
def update_avatar():
    if "user" not in session:
        return redirect(url_for("home"))

    new_avatar = request.form.get("avatar", "").strip()
    if not new_avatar:
        return redirect(url_for("profile"))

    user_file = os.path.join(USER_DIR, f"{session['user']}.json")
    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    user_data["avatar"] = new_avatar

    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

    return redirect(url_for("profile"))

@app.route("/set-mode", methods=["POST"])
@login_required
def set_mode():
    if "user" not in session:
        return redirect(url_for("home"))

    mode = request.form.get("mode")
    if mode in ["libre", "themes_faibles", "reviser"]:
        session["mode"] = mode
    else:
        session["mode"] = "libre"  # fallback/default

    return redirect(url_for("quiz"))


# --- Quiz Route ---
@app.route("/quiz")
@login_required
def quiz():
    if "user" not in session:
        return redirect(url_for("home"))

    user_file = os.path.join(USER_DIR, f"{session['user']}.json")
    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    mode = session.get("mode", "libre")
    today = date.today().isoformat()

    # ✅ Initialize codestan session if not present
    if "codestan_session" not in session:
        session["codestan_session"] = {
            "start_time": datetime.now().isoformat(),
            "mode": mode,
            "answered": 0,
            "correct": 0,
            "wrong": 0,
            "score": 0
        }

    # ✅ Extract stats to display
    global_stats = {
        "score": user_data["score"],
        "best_streak": user_data["best_streak"],
        "answered": user_data["total_answered"],
        "success_rate": user_data["success_rate_overall"]
    }

    daily = user_data.get("daily_stats", {}).get(today, {
        "score": 0, "answered": 0, "correct": 0, "wrong": 0, "success_rate": 0
    })
    today_stats = {
        "score": daily["score"],
        "answered": daily["answered"],
        "success_rate": daily.get("success_rate", 0),
        "current_streak": user_data.get("current_streak", 0)
    }

    # ✅ Select questions based on mode
    if mode == "libre":
        question_pool = questions

    elif mode == "themes_faibles":
        theme_stats = user_data.get("theme_stats", {})
        if not theme_stats:
            question_pool = questions
        else:
            sorted_themes = sorted(
                theme_stats.items(),
                key=lambda item: item[1]["correct"] / item[1]["answered"] if item[1]["answered"] > 0 else 0
            )
            worst_themes = [t[0] for t in sorted_themes[:2]]
            question_pool = [q for q in questions if q["theme"] in worst_themes]

    elif mode == "reviser":
        incorrect_ids = set(user_data.get("incorrect_questions", []))
        question_pool = [q for q in questions if q["ID"] in incorrect_ids]
    else:
        question_pool = questions

    if not question_pool:
        return "Aucune question disponible pour ce mode."

    # === No-repeat selection ===
    eligible_ids = [q["ID"] for q in question_pool]
    next_id = pick_next_in_cycle(user_data, eligible_ids, mode=mode, theme=None)

    # Map ID -> question object
    pool_by_id = {q["ID"]: q for q in question_pool}
    question = pool_by_id.get(next_id, random.choice(question_pool))  # safe fallback

    # Persist rotation immediately
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

    # Answers (as before)
    all_answers = question["answers"]["correct"] + question["answers"]["wrong"]
    random.shuffle(all_answers)

    return render_template(
        "index.html",
        question=question,
        answers=all_answers,
        session_avatar=user_data.get("avatar", "default.png"),
        global_stats=global_stats,
        today_stats=today_stats
    )

@app.route("/flag-question", methods=["POST"])
@login_required
def flag_question():
    data = request.get_json(silent=True) or {}

    qid = data.get("question_id")
    comment = (data.get("comment") or "").strip()
    mode = data.get("mode")
    theme = data.get("theme")

    if not qid or not comment:
        return {"ok": False, "error": "Missing question_id or comment"}, 400

    # Try to capture reporter email from the current user JSON (keeps it simple)
    email = None
    try:
        user_key = session.get("user")
        if user_key:
            user_file = os.path.join(USER_DIR, f"{user_key}.json")
            if os.path.exists(user_file):
                with open(user_file, "r", encoding="utf-8") as f:
                    user_data = json.load(f)
                    email = (user_data.get("email") or "").strip().lower()
    except Exception:
        pass  # non-blocking

    # Save to DB
    with SessionLocal() as db:
        db.add(Flag(
            question_id=str(qid),
            email=email,
            mode=mode,
            theme=theme,
            comment=comment
        ))
        db.commit()

    return {"ok": True}

@app.route("/submit-answer", methods=["POST"])
@login_required
def submit_answer():
    if "user" not in session:
        return "Unauthorized", 401

    data = request.get_json()
    question_id = data.get("question_id")
    user_answers = data.get("user_answers", [])
    is_correct = data.get("is_correct")
    theme = data.get("theme")

    user_file = os.path.join(USER_DIR, f"{session['user']}.json")
    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    # ✅ ensure dicts exist for older profiles
    user_data.setdefault("daily_stats", {})
    user_data.setdefault("monthly_stats", {})
    user_data.setdefault("theme_stats", {})

    # === GLOBAL STATS ===
    user_data["total_answered"] += 1
    if is_correct:
        user_data["total_correct"] += 1
        user_data["score"] += 1
        user_data["current_streak"] += 1
        user_data["best_streak"] = max(user_data["best_streak"], user_data["current_streak"])
    else:
        user_data["total_wrong"] += 1
        user_data["score"] -= 1
        user_data["current_streak"] = 0
        if question_id not in user_data["incorrect_questions"]:
            user_data["incorrect_questions"].append(question_id)

    # === SUCCESS RATE ===
    if user_data["total_answered"] > 0:
        user_data["success_rate_overall"] = round(
            100 * user_data["total_correct"] / user_data["total_answered"], 1
        )

    # === DAILY STATS (Europe/Paris) ===
    today_paris = datetime.now(PARIS).date().isoformat()

    daily = user_data["daily_stats"].get(today_paris, {
        "answered": 0,
        "correct": 0,
        "wrong": 0,
        "score": 0,
        "success_rate": 0.0
    })

    # Was this the FIRST answer of the day?
    first_answer_today = (daily["answered"] == 0)

    daily["answered"] += 1
    if is_correct:
        daily["correct"] += 1
        daily["score"] += 1
    else:
        daily["wrong"] += 1
        daily["score"] -= 1

    if daily["answered"] > 0:
        daily["success_rate"] = round(100 * daily["correct"] / daily["answered"], 1)

    user_data["daily_stats"][today_paris] = daily

    # === MONTHLY STATS ===
    month = today_paris[:7]
    monthly = user_data["monthly_stats"].get(month, {
        "answered": 0,
        "correct": 0,
        "wrong": 0,
        "score": 0,
        "success_rate": 0.0
    })
    monthly["answered"] += 1
    if is_correct:
        monthly["correct"] += 1
        monthly["score"] += 1
    else:
        monthly["wrong"] += 1
        monthly["score"] -= 1
    if monthly["answered"] > 0:
        monthly["success_rate"] = round(100 * monthly["correct"] / monthly["answered"], 1)
    user_data["monthly_stats"][month] = monthly

    # === THEME STATS ===
    theme_stats = user_data["theme_stats"].get(theme, {
        "answered": 0,
        "correct": 0,
        "wrong": 0
    })
    theme_stats["answered"] += 1
    if is_correct:
        theme_stats["correct"] += 1
    else:
        theme_stats["wrong"] += 1
    user_data["theme_stats"][theme] = theme_stats

    # === Recalculate best/worst theme ===
    if user_data["theme_stats"]:
        theme_success = []
        has_any_wrong = False

        for theme, stats in user_data["theme_stats"].items():
            if stats["answered"] > 0:
                success_rate = stats["correct"] / stats["answered"]
                theme_success.append((theme, success_rate))
                if stats["wrong"] > 0:
                    has_any_wrong = True

        if not has_any_wrong:
            user_data["worst_theme"] = None
            user_data["best_theme"] = None
        elif theme_success:
            theme_success.sort(key=lambda t: t[1])
            worst = round(theme_success[0][1], 4)
            best = round(theme_success[-1][1], 4)
            if worst != best:
                user_data["worst_theme"] = theme_success[0][0]
                user_data["best_theme"] = theme_success[-1][0]
            else:
                user_data["worst_theme"] = None
                user_data["best_theme"] = None
        else:
            user_data["worst_theme"] = None
            user_data["best_theme"] = None

    # === Update session stats ===
    if "codestan_session" in session:
        s = session["codestan_session"]
        s["answered"] += 1
        s["correct"] += 1 if is_correct else 0
        s["wrong"] += 0 if is_correct else 1
        s["score"] += 1 if is_correct else -1

    # ✅ Increment the login streak only after the first answered question of the day
    if first_answer_today:
        update_login_streak(user_data)

    # === Save updated stats ===
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

    # ✅ keep DB in sync with the just-updated JSON
    sync_user_to_db_from_json(user_data)

    return {"success": True}

def finalize_active_session(user_data):
    if "codestan_session" not in session:
        return

    s = session["codestan_session"]
    end_time = datetime.now()
    start_time = datetime.fromisoformat(s["start_time"])
    duration = int((end_time - start_time).total_seconds() // 60)

    # Skip logging empty sessions
    if s["answered"] == 0:
        session.pop("codestan_session", None)
        return

    # ✅ accumulate total time spent
    user_data["time_spent_minutes"] = user_data.get("time_spent_minutes", 0) + max(duration, 0)

    session_data = {
        "date": datetime.now().date().isoformat(),
        "mode": s["mode"],
        "start_time": s["start_time"].split("T")[-1],
        "end_time": end_time.strftime("%H:%M:%S"),
        "duration_minutes": duration,
        "answered": s["answered"],
        "correct": s["correct"],
        "wrong": s["wrong"],
        "score": s["score"],
        "success_rate": round(100 * s["correct"] / s["answered"], 1) if s["answered"] else 0
    }

    user_data.setdefault("session_log", []).append(session_data)
    session.pop("codestan_session", None)

    # ✅ keep DB in sync when a session ends (time_spent_minutes, etc.)
    sync_user_to_db_from_json(user_data)

# --- Run the app ---
if __name__ == "__main__":
    app.run(debug=True)
