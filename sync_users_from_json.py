import os
import json
from datetime import datetime

from db import SessionLocal, engine
from models import Base, User

USER_DIR = "users"

def parse_dt(s):
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None

def main():
    # Ensure tables exist (safe to call)
    Base.metadata.create_all(bind=engine)

    if not os.path.isdir(USER_DIR):
        print(f"No '{USER_DIR}' folder found. Nothing to import.")
        return

    files = [f for f in os.listdir(USER_DIR) if f.endswith(".json")]
    if not files:
        print("No user JSON files found to import.")
        return

    session = SessionLocal()
    created, updated, skipped = 0, 0, 0

    try:
        for fname in files:
            path = os.path.join(USER_DIR, fname)
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            email = data.get("email")
            name = data.get("name") or data.get("avatar_name") or "user"

            if not email:
                print(f"⚠️  Skipping {fname}: missing 'email'")
                skipped += 1
                continue

            # Find existing by unique email
            user = session.query(User).filter_by(email=email).first()

            # Defaults to guard older files
            data.setdefault("daily_stats", {})
            data.setdefault("monthly_stats", {})
            data.setdefault("theme_stats", {})
            data.setdefault("incorrect_questions", [])
            data.setdefault("login_streak", {})

            if user is None:
                user = User(
                    email=email,
                    name=name,
                    avatar_name=data.get("avatar_name"),
                    avatar=data.get("avatar"),
                    password_hash=data.get("password_hash", ""),
                    secret_question=data.get("secret_question"),
                    secret_answer_hash=data.get("secret_answer_hash"),
                    created_at=parse_dt(data.get("created_at")) or datetime.utcnow(),
                    last_login=parse_dt(data.get("last_login")),

                    score=int(data.get("score", 0)),
                    current_streak=int(data.get("current_streak", 0)),
                    best_streak=int(data.get("best_streak", 0)),
                    total_answered=int(data.get("total_answered", 0)),
                    total_correct=int(data.get("total_correct", 0)),
                    total_wrong=int(data.get("total_wrong", 0)),
                    success_rate_overall=float(data.get("success_rate_overall", 0.0)),
                    time_spent_minutes=int(data.get("time_spent_minutes", 0)),

                    daily_stats=data.get("daily_stats", {}),
                    monthly_stats=data.get("monthly_stats", {}),
                    theme_stats=data.get("theme_stats", {}),
                    best_theme=data.get("best_theme"),
                    worst_theme=data.get("worst_theme"),
                    incorrect_questions=data.get("incorrect_questions", []),

                    login_streak=data.get("login_streak", {}),

                    free_forever=bool(data.get("free_forever", False)),
                    plan=data.get("plan", "free"),
                    quota_used=int(data.get("quota_used", 0)),
                )
                session.add(user)
                created += 1
            else:
                # Update existing
                user.name = name
                user.avatar_name = data.get("avatar_name")
                user.avatar = data.get("avatar")
                user.password_hash = data.get("password_hash", user.password_hash)
                user.secret_question = data.get("secret_question")
                user.secret_answer_hash = data.get("secret_answer_hash")
                user.last_login = parse_dt(data.get("last_login")) or user.last_login

                user.score = int(data.get("score", user.score or 0))
                user.current_streak = int(data.get("current_streak", user.current_streak or 0))
                user.best_streak = int(data.get("best_streak", user.best_streak or 0))
                user.total_answered = int(data.get("total_answered", user.total_answered or 0))
                user.total_correct = int(data.get("total_correct", user.total_correct or 0))
                user.total_wrong = int(data.get("total_wrong", user.total_wrong or 0))
                user.success_rate_overall = float(data.get("success_rate_overall", user.success_rate_overall or 0.0))
                user.time_spent_minutes = int(data.get("time_spent_minutes", user.time_spent_minutes or 0))

                user.daily_stats = data.get("daily_stats", user.daily_stats or {})
                user.monthly_stats = data.get("monthly_stats", user.monthly_stats or {})
                user.theme_stats = data.get("theme_stats", user.theme_stats or {})
                user.best_theme = data.get("best_theme", user.best_theme)
                user.worst_theme = data.get("worst_theme", user.worst_theme)
                user.incorrect_questions = data.get("incorrect_questions", user.incorrect_questions or [])

                user.login_streak = data.get("login_streak", user.login_streak or {})

                user.free_forever = bool(data.get("free_forever", user.free_forever or False))
                user.plan = data.get("plan", user.plan or "free")
                user.quota_used = int(data.get("quota_used", user.quota_used or 0))

                updated += 1

        session.commit()
        print(f"✅ Import done — created: {created}, updated: {updated}, skipped: {skipped}")

    except Exception as e:
        session.rollback()
        print("❌ Import failed:", e)
        raise
    finally:
        session.close()

if __name__ == "__main__":
    main()
