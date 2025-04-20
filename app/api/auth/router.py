# app/api/auth/router.py
from datetime import timedelta, datetime
from typing import Any, Dict
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...core.security import get_password_hash
from ...core.config import settings
from .jwt import authenticate_user, create_access_token
from ..users.models import User
from ..users.schemas import UserCreate, UserResponse, Token

# ロガーの設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/token", response_model=Token)
def login_for_access_token(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    OAuth2互換のトークンログインエンドポイント
    """
    logger.info(f"ログイン試行: {form_data.username}")
    
    user = authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        logger.warning(f"ログイン失敗: {form_data.username}")
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
        logger.error(f"ログイン時間の更新エラー: {str(e)}")
        db.rollback()  # エラー時はロールバック
    
    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.user_id)},
        expires_delta=access_token_expires
    )
    
    # CORS対応のためにヘッダーを設定
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    
    logger.info(f"ログイン成功: {form_data.username}, user_id: {user.user_id}")
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_id": user.user_id,
        "user_name": user.name
    }

@router.post("/login", response_model=Token)
def login(
    response: Response,
    username: str,
    password: str,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    ユーザー名とパスワードでログイン
    """
    logger.info(f"ログイン試行: {username}")
    
    user = authenticate_user(db, username, password)
    
    if not user:
        logger.warning(f"ログイン失敗: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー名またはパスワードが無効です",
        )
    
    # 最終ログイン時間を更新
    try:
        user.last_login_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        logger.error(f"ログイン時間の更新エラー: {str(e)}")
        db.rollback()  # エラー時はロールバック
    
    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.user_id)},
        expires_delta=access_token_expires
    )
    
    # CORS対応のためにヘッダーを設定
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    
    logger.info(f"ログイン成功: {username}, user_id: {user.user_id}")
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_id": user.user_id,
        "user_name": user.name
    }


@router.post("/register", response_model=Token)
def register_user(
    response: Response,
    user_data: UserCreate,
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """
    新規ユーザー登録
    """
    logger.info(f"ユーザー登録試行: {user_data.name}")
    
    # パスワード確認
    if user_data.password != user_data.confirm_password:
        logger.warning(f"パスワード不一致: {user_data.name}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="パスワードが一致しません",
        )
    
    # ユーザー名の重複チェック
    existing_user = db.query(User).filter(User.name == user_data.name).first()
    if existing_user:
        logger.warning(f"ユーザー名重複: {user_data.name}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="このユーザー名は既に使用されています",
        )
    
    # 新しいユーザーを作成
    try:
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
        
        # CORS対応のためにヘッダーを設定
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        
        logger.info(f"ユーザー登録成功: {user_data.name}, user_id: {user.user_id}")
        
        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "user_id": user.user_id,
            "user_name": user.name
        }
    except Exception as e:
        db.rollback()
        logger.error(f"ユーザー登録エラー: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"ユーザー登録中にエラーが発生しました: {str(e)}",
        )