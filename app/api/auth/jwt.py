# app/api/auth/jwt.py
from datetime import datetime, timedelta
from typing import Optional
import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

# 相対インポート
from ...core.database import get_db
from ...core.security import verify_password, SECRET_KEY, ALGORITHM
from ...core.config import settings
from ..users.models import User
from ..users.schemas import TokenData

# ロガーの設定
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OAuth2のパスワードベアラースキーマを定義
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/token", auto_error=False)

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """ユーザー名とパスワードでユーザーを認証する"""
    try:
        # データベースからユーザーを検索
        user = db.query(User).filter(User.name == username).first()
        
        if not user:
            logger.warning(f"ユーザーが見つかりません: {username}")
            return None
        
        # パスワード検証
        if verify_password(password, user.password):
            return user
        
        logger.warning(f"パスワードが一致しません: {username}")
        return None
    except Exception as e:
        # エラーの詳細をログ出力
        logger.error(f"認証エラー: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    """
    現在のユーザーを取得する
    
    :param db: データベースセッション
    :param token: アクセストークン
    :return: 現在のユーザー
    :raises: 認証エラーの場合はHTTPException
    """
    # トークンがない場合は認証されていないと判断
    if token is None:
        logger.warning("認証トークンがありません")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="認証情報が必要です",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # トークンをデコード
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        
        if user_id is None:
            logger.warning("トークンにユーザーIDがありません")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="無効な認証トークンです",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # 文字列をintに変換する可能性がある
        if isinstance(user_id, str):
            try:
                user_id = int(user_id)
            except ValueError:
                logger.error(f"ユーザーIDを整数に変換できません: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="無効な認証トークン形式です",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        token_data = TokenData(user_id=user_id)
    except JWTError as e:
        logger.error(f"JWTエラー: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="無効な認証トークンです",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # ユーザーIDを使用してユーザーを検索
    user = db.query(User).filter(User.user_id == token_data.user_id).first()
    
    if user is None:
        logger.warning(f"ユーザーIDに対応するユーザーが見つかりません: {token_data.user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザーが存在しません",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    JWTアクセストークンを生成する
    
    :param data: トークンに含めるデータ（通常はユーザーID）
    :param expires_delta: トークンの有効期限
    :return: エンコードされたJWTトークン
    """
    to_encode = data.copy()
    
    # 有効期限の設定
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    
    # トークンをエンコード
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    
    return encoded_jwt