import os
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.types import JSON as JSONType
from db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    # Identity & auth
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)          # avatar display name
    avatar_name = Column(String, nullable=True)
    avatar = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    secret_question = Column(String, nullable=True)
    secret_answer_hash = Column(String, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Global stats
    score = Column(Integer, default=0)
    current_streak = Column(Integer, default=0)
    best_streak = Column(Integer, default=0)
    total_answered = Column(Integer, default=0)
    total_correct = Column(Integer, default=0)
    total_wrong = Column(Integer, default=0)
    success_rate_overall = Column(Float, default=0.0)
    time_spent_minutes = Column(Integer, default=0)

    # Aggregates (mirror your JSON shapes)
    daily_stats = Column(JSONType, default=dict)        # { "YYYY-MM-DD": {...} }
    monthly_stats = Column(JSONType, default=dict)      # { "YYYY-MM": {...} }
    theme_stats = Column(JSONType, default=dict)        # { theme: {...} }
    best_theme = Column(String, nullable=True)
    worst_theme = Column(String, nullable=True)
    incorrect_questions = Column(JSONType, default=list)

    # Login streak object
    login_streak = Column(JSONType, default=dict)       # { "last_date": "...", "count": N, "best": N }

    # Monetization flags
    free_forever = Column(Boolean, default=False)
    plan = Column(String, default="free")
    quota_used = Column(Integer, default=0)
