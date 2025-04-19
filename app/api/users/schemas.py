# app/api/users/schemas.py
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from ...schemas.base import BaseSchemaModel

class UserBase(BaseSchemaModel):
    name: str = Field(..., min_length=1, max_length=50, description="ユーザー名")

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="パスワード")
    confirm_password: str = Field(..., description="確認用パスワード")
    categories: List[str] = Field(default=[], description="ユーザーの興味/専門カテゴリー")

class UserUpdate(BaseSchemaModel):
    name: Optional[str] = Field(None, min_length=1, max_length=50, description="ユーザー名")
    password: Optional[str] = Field(None, min_length=8, description="パスワード")
    confirm_password: Optional[str] = Field(None, description="確認用パスワード")
    categories: Optional[List[str]] = Field(None, description="ユーザーの興味/専門カテゴリー")

class UserResponse(UserBase):
    id: int
    categories: List[str]
    points: int = 0
    created_at: datetime

class UserLogin(BaseSchemaModel):
    name: str
    password: str

class Token(BaseSchemaModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    user_name: str

class TokenData(BaseSchemaModel):
    user_id: Optional[int] = None
