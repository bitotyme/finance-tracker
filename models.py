from sqlalchemy import Column, Integer, String, Float, Date, DateTime, ForeignKey
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)  # NEW (required)
    hashed_password = Column(String, nullable=False)

    # NEW: password reset fields
    reset_token_hash = Column(String, nullable=True)
    reset_token_expires_at = Column(DateTime, nullable=True)

    # relationships
    goal = relationship("Goal", back_populates="user", uselist=False, cascade="all, delete-orphan")
    entries = relationship("Entry", back_populates="user", cascade="all, delete-orphan")


class Goal(Base):
    __tablename__ = "goals"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)

    starting_total = Column(Float, default=0)
    goal_amount = Column(Float, nullable=False)

    user = relationship("User", back_populates="goal")


class Entry(Base):
    __tablename__ = "entries"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    date = Column(Date, nullable=False)
    amount_added = Column(Float, nullable=False)
    total_after = Column(Float, nullable=False)

    user = relationship("User", back_populates="entries")
