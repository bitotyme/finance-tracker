from datetime import date
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class GoalSetRequest(BaseModel):
    starting_total: float
    goal_amount: float


class EntryCreateRequest(BaseModel):
    date: date
    amount_added: float


class EntryOut(BaseModel):
    date: date
    amount_added: float
    total_after: float


class MeResponse(BaseModel):
    username: str
    goal_amount: Optional[float] = None
    starting_total: float = 0
    entries: List[EntryOut] = Field(default_factory=list)


# NEW: Forgot / Reset password
class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
