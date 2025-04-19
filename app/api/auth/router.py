# app/api/auth/router.py
from datetime import timedelta, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...core.security import get_password_hash
from ...core.config import settings
from .jwt import authenticate_user, create_access_token
from ..users.models import User
from ..users.schemas import UserCreate, UserResponse, Token

router = APIRouter()

@router.post("/token", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
) -> Any:
    """
    OAuth2互換のトークンログインエンドポイント
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー名またはパスワードが無効です",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # 最終ログイン時間を更新
    try:
        user.last_login_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        print(f"ログイン時間の更新エラー: {str(e)}")
        db.rollback()  # エラー時はロールバック
    
    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.user_id)},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_id": user.user_id,
        "user_name": user.name
    }

@router.post("/login", response_model=Token)
def login(
    username: str,
    password: str,
    db: Session = Depends(get_db)
) -> Any:
    """
    ユーザー名とパスワードでログイン
    """
    user = authenticate_user(db, username, password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー名またはパスワードが無効です",
        )
    
    # 最終ログイン時間を更新
    try:
        user.last_login_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        print(f"ログイン時間の更新エラー: {str(e)}")
        db.rollback()  # エラー時はロールバック
    
    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.user_id)},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_id": user.user_id,
        "user_name": user.name
    }

@router.post("/register", response_model=Token)
def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db)
) -> Any:
    """
    新規ユーザー登録
    """
    # パスワード確認
    if user_data.password != user_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="パスワードが一致しません",
        )
    
    # ユーザー名の重複チェック
    existing_user = db.query(User).filter(User.name == user_data.name).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="このユーザー名は既に使用されています",
        )
    
    # 新しいユーザーを作成
    user = User(
        name=user_data.name,
        password=get_password_hash(user_data.password),
        categories=",".join(user_data.categories) if user_data.categories else "",
        point_total=0,
        last_login_at=datetime.utcnow()
    )
    
    # データベースに保存
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.user_id)},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_id": user.user_id,
        "user_name": user.name
    }