from flask import Flask, render_template, request, redirect, session, url_for
import json
import random
import os
import hashlib
import secrets
from datetime import datetime, date, timedelta
import re

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Secure session key

# --- Paths and constants ---
QUESTION_FILE = "set_ok_cleaned.json"
USER_DIR = "users"

# --- Utility functions ---
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def get_known_users():
    if not os.path.exists(USER_DIR):
        return []
    return [filename.replace(".json", "") for filename in os.listdir(USER_DIR) if filename.endswith(".json")]

def email_to_id(email: str) -> str:
    base = email.strip().lower()
    return re.sub(r'[^a-z0-9]+', '_', base).strip('_')

# --- Question Logic ---
with open(QUESTION_FILE, "r", encoding="utf-8") as f:
    questions = json.load(f)

def get_random_question():
    """Returns one random question from the list."""
    return random.choice(questions)

# --- Home page ---
@app.route("/login-email", methods=["POST"])
def login_email():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "").strip()
    if not email or not password:
        return render_template("home.html", error="Merci d’entrer e‑mail et mot de passe.")

    name = email_to_id(email)  # reuse existing name-based storage
    user_file = os.path.join(USER_DIR, f"{name}.json")

    if os.path.exists(user_file):
        with open(user_file, "r", encoding="utf-8") as f:
            user_data = json.load(f)
        if user_data.get("password_hash") != hash_text(password):
            return render_template("home.html", error="E‑mail ou mot de passe incorrect.")
        session["user"] = name
        # update last_login
        user_data["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(user_file, "w", encoding="utf-8") as f:
            json.dump(user_data, f, indent=2, ensure_ascii=False)
        return redirect(url_for("profile"))

    # New user → send to your existing register flow (same template)
    avatar_dir = os.path.join("static", "avatars")
    avatars = [f for f in os.listdir(avatar_dir) if f.lower().endswith(".png")]
    avatars.sort()
    return render_template("register.html", name=name, avatars=avatars)


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
def stats():
    if "user" not in session:
        return redirect(url_for("home"))

    user_file = os.path.join(USER_DIR, f"{session['user']}.json")
    with open(user_file, "r", encoding="utf-8") as f:
        user_data = json.load(f)

    return render_template("stats.html", user_data=user_data)

@app.route("/update-avatar", methods=["POST"])
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

    question = random.choice(question_pool)
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


@app.route("/submit-answer", methods=["POST"])
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

    # === DAILY STATS ===
    today = date.today().isoformat()
    daily = user_data["daily_stats"].get(today, {
        "answered": 0,
        "correct": 0,
        "wrong": 0,
        "score": 0,
        "success_rate": 0.0
    })
    daily["answered"] += 1
    if is_correct:
        daily["correct"] += 1
        daily["score"] += 1
    else:
        daily["wrong"] += 1
        daily["score"] -= 1
    if daily["answered"] > 0:
        daily["success_rate"] = round(100 * daily["correct"] / daily["answered"], 1)
    user_data["daily_stats"][today] = daily

    # === MONTHLY STATS ===
    month = today[:7]
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

    # === Save updated stats ===
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f, indent=2, ensure_ascii=False)

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



# --- Run the app ---
if __name__ == "__main__":
    app.run(debug=True)




HOME.HTML


<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Bienvenue au Codestan</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f7f9fc;
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        .avatar-thumb {
            height: 50px;
            width: 50px;
            object-fit: cover;
            border-radius: 50%;
        }
        .neon {
            /* Optional future neon glow */
            color: #0ff;
            text-shadow: 0 0 5px #0ff, 0 0 10px #0ff, 0 0 15px #0ff;
        }
    </style>
</head>

<body>
<div class="container">
    <div class="row">
        <!-- 🧳 Left Side (2/3) -->
        <div class="col-md-8 text-center">
            <h1 class="mb-4">Bienvenue au Codestan 🛂</h1>

            <img src="{{ url_for('static', filename='ui/border_entry_codestan.png') }}"
                 alt="Entrée Codestan"
                 class="img-fluid rounded shadow-sm mb-4" style="max-height: 400px;">

            <p class="lead text-center">Veuillez présenter votre passeport pour entrer dans la zone d'entraînement.</p>

            <form method="POST" action="/login-email" class="mt-4" style="max-width: 500px; margin: auto;">
              <div class="mb-3 text-center">
                <label for="email" class="form-label fs-5 text-center">Adresse e‑mail</label>
                <input type="email"
                       class="form-control form-control-lg text-center"
                       id="email"
                       name="email"
                       required
                       autocomplete="email"
                       placeholder="votre@email.com">
              </div>

              <div class="mb-3 text-center">
                <label for="password" class="form-label">Mot de passe</label>
                <input type="password"
                       class="form-control text-center"
                       id="password"
                       name="password"
                       required
                       autocomplete="current-password"
                       placeholder="Entrez votre mot de passe">
              </div>

              {% if error %}
                <div class="alert alert-danger text-center">{{ error }}</div>
              {% endif %}

              <div class="text-center mt-3">
                <button type="submit" class="btn btn-success btn-lg">Se connecter</button>
              </div>

              <div class="text-center mt-3">
                <span class="text-muted">Pas encore de compte ? Saisissez votre e‑mail et un mot de passe, puis validez — on vous crée le profil.</span>
              </div>
            </form>


        </div>

        <!-- 🏆 Right Side: Leaderboard -->
        <div class="col-md-4 mt-4 mt-md-0">
          <div class="card shadow-sm">
            <div class="card-body">
              <h5 class="card-title text-center">🏆 Classement général</h5>

              <!-- Meilleur score -->
              <div class="text-center mb-4 pb-3 border-bottom">
                <p class="fw-bold mb-2">🥇 Meilleur score</p>
                {% if top_score %}
                  <img src="{{ url_for('static', filename='avatars/' ~ top_score.avatar) }}" class="avatar-thumb mb-2">
                  <p>{{ top_score.name | capitalize }} — {{ top_score.score }} pts</p>
                {% else %}
                  <p class="text-muted">Aucun score disponible</p>
                {% endif %}
              </div>

              <!-- Meilleure série -->
              <div class="text-center mb-4 pb-3 border-bottom">
                <p class="fw-bold mb-2">🔥 Meilleure série</p>
                {% if top_streak %}
                  <img src="{{ url_for('static', filename='avatars/' ~ top_streak.avatar) }}" class="avatar-thumb mb-2">
                  <p>{{ top_streak.name | capitalize }} — {{ top_streak.best_streak }} bonnes réponses</p>
                {% else %}
                  <p class="text-muted">Aucune série disponible</p>
                {% endif %}
              </div>

              <!-- Connexions consécutives -->
              <div class="text-center">
                <p class="fw-bold mb-2">📆 Connexions consécutives</p>
                {% if top_login %}
                  <img src="{{ url_for('static', filename='avatars/' ~ top_login.avatar) }}" class="avatar-thumb mb-2">
                  <p>{{ top_login.name | capitalize }} — {{ top_login.get("login_streak", 0) }} jours</p>
                {% else %}
                  <p class="text-muted">Aucune donnée</p>
                {% endif %}
              </div>
            </div>
          </div>
        </div>
    </div>
</div>

<script>
  const knownUsers = {{ known_users | tojson }};
  const passwordWrapper = document.getElementById("password-wrapper");

  function checkName(value) {
    const name = value.trim().toLowerCase();
    if (knownUsers.includes(name)) {
      passwordWrapper.style.display = "block";
    } else {
      passwordWrapper.style.display = "none";
    }
  }
</script>


</body>
</html>
