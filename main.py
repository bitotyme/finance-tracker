from dotenv import load_dotenv
load_dotenv()

import os
import urllib.parse
import urllib.request
import json
from datetime import datetime, timedelta
import secrets
import hashlib

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy.orm import Session

from database import engine, SessionLocal
from models import Base, User, Goal, Entry
from schemas import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    MeResponse,
    GoalSetRequest,
    EntryCreateRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_token,
)

app = FastAPI(title="Student Finance Planner API")

Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://csci480project.netlify.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        username = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

# ---- Email + reset helpers ----
FRONTEND_RESET_URL = os.environ.get(
    "FRONTEND_RESET_URL",
    "https://csci480project.netlify.app/reset-password.html"
)
RESET_TOKEN_MINUTES = int(os.environ.get("RESET_TOKEN_MINUTES", "15"))

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def send_reset_email(to_email: str, reset_link: str) -> None:
    api_key = os.environ["SMTP_PASS"]
    from_email = os.environ["FROM_EMAIL"]

    print("send_reset_email() called for:", to_email)

    payload = json.dumps({
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_email},
        "subject": "Finance Tracker Password Reset",
        "content": [{
            "type": "text/plain",
            "value": (
                f"You requested a password reset.\n\n"
                f"Click this link to reset your password:\n{reset_link}\n\n"
                f"This link expires in {RESET_TOKEN_MINUTES} minutes.\n"
                "If you did not request this, you can ignore this email."
            )
        }]
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.sendgrid.com/v3/mail/send",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST"
    )

    with urllib.request.urlopen(req) as resp:
        print("Reset email sent successfully. Status:", resp.status)

# ---- Health / test routes ----
@app.get("/")
def root():
    return {"message": "Finance Tracker API is running"}

@app.get("/health")
def health_check():
    return {"status": "ok"}

# ---- Auth routes ----
@app.post("/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    username = payload.username.strip()
    email = payload.email.strip().lower()
    password = payload.password.strip()

    if not username or not email or not password:
        raise HTTPException(status_code=400, detail="Username, email, and password required")

    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Username already taken")

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already in use")

    user = User(username=username, email=email, hashed_password=hash_password(password))
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "User created"}

@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    username = payload.username.strip()
    password = payload.password.strip()

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(subject=username)
    return TokenResponse(access_token=token)

@app.post("/token", response_model=TokenResponse)
def token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    username = form_data.username.strip()
    password = form_data.password.strip()

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(subject=username)
    return TokenResponse(access_token=token)

# ---- Forgot / Reset password routes ----
@app.post("/forgot-password")
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    email = payload.email.strip().lower()
    generic = {"message": "If that email exists, a reset link has been sent."}

    print("Forgot password requested for:", email)

    user = db.query(User).filter(User.email == email).first()
    print("User found:", bool(user))

    if not user:
        return generic

    raw_token = secrets.token_urlsafe(32)
    user.reset_token_hash = hash_token(raw_token)
    user.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_MINUTES)
    db.commit()

    reset_link = f"{FRONTEND_RESET_URL}?token={urllib.parse.quote(raw_token)}"
    print("Reset link generated:", reset_link)

    try:
        send_reset_email(user.email, reset_link)
    except KeyError as e:
        print(f"ERROR: Missing environment variable: {e}")
    except Exception as e:
        print(f"ERROR: Failed to send reset email: {e}")

    return generic

@app.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    token = urllib.parse.unquote(payload.token.strip())
    new_password = payload.new_password.strip()

    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    token_h = hash_token(token)
    user = db.query(User).filter(User.reset_token_hash == token_h).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    if not user.reset_token_expires_at or user.reset_token_expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Reset token expired")

    user.hashed_password = hash_password(new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    db.commit()

    return {"message": "Password updated successfully"}

# ---- App routes ----
@app.get("/me", response_model=MeResponse)
def me(current_user: User = Depends(get_current_user)):
    goal_amount = None
    starting_total = 0

    if current_user.goal:
        goal_amount = current_user.goal.goal_amount
        starting_total = current_user.goal.starting_total or 0

    entries_out = [
        {
            "date": e.date,
            "amount_added": e.amount_added,
            "total_after": e.total_after,
        }
        for e in current_user.entries
    ]
    entries_out.sort(key=lambda x: x["date"])

    return {
        "username": current_user.username,
        "goal_amount": goal_amount,
        "starting_total": starting_total,
        "entries": entries_out,
    }

@app.post("/goal")
def set_goal(
    payload: GoalSetRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.goal_amount <= 0:
        raise HTTPException(status_code=400, detail="goal_amount must be > 0")
    if payload.starting_total < 0:
        raise HTTPException(status_code=400, detail="starting_total must be >= 0")

    if current_user.goal:
        current_user.goal.goal_amount = float(payload.goal_amount)
        current_user.goal.starting_total = float(payload.starting_total)
    else:
        db.add(
            Goal(
                user_id=current_user.id,
                goal_amount=float(payload.goal_amount),
                starting_total=float(payload.starting_total),
            )
        )

    db.commit()
    return {"message": "Goal set"}

@app.post("/entry")
def add_entry(
    payload: EntryCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.amount_added == 0:
        raise HTTPException(status_code=400, detail="amount_added must not be 0")

    last_entry = (
        db.query(Entry)
        .filter(Entry.user_id == current_user.id)
        .order_by(Entry.date.desc(), Entry.id.desc())
        .first()
    )

    if last_entry:
        current_total = float(last_entry.total_after)
    else:
        current_total = float(current_user.goal.starting_total) if current_user.goal else 0.0

    new_total = current_total + float(payload.amount_added)

    existing = (
        db.query(Entry)
        .filter(Entry.user_id == current_user.id, Entry.date == payload.date)
        .first()
    )

    if existing:
        existing.amount_added = float(existing.amount_added) + float(payload.amount_added)
        existing.total_after = float(existing.total_after) + float(payload.amount_added)
    else:
        db.add(
            Entry(
                user_id=current_user.id,
                date=payload.date,
                amount_added=float(payload.amount_added),
                total_after=new_total,
            )
        )

    db.commit()
    return {"message": "Entry added"}

@app.post("/reset")
def reset_data(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db.query(Entry).filter(Entry.user_id == current_user.id).delete()
    db.query(Goal).filter(Goal.user_id == current_user.id).delete()
    db.commit()
    return {"message": "Reset complete"}