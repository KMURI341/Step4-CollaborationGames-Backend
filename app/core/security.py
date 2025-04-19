# app/core/security.py の内容を以下のように変更

from datetime import datetime, timedelta
from typing import Optional

from jose import jwt
from passlib.context import CryptContext

# 相対インポートに変更
from .config import settings

# 以下の2つの変数を追加
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

# パスワードハッシュ用のコンテキスト
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, stored_password: str) -> bool:
    """
    平文のパスワードとデータベースに保存されたパスワードを検証する
    開発環境では直接比較も許可
    """
    # 開発環境では単純な文字列比較も許可
    if settings.DEBUG and plain_password == stored_password:
        return True
    # 通常のハッシュ検証
    return pwd_context.verify(plain_password, stored_password)

def get_password_hash(password: str) -> str:
    """パスワードをハッシュ化する"""
    # 開発環境ではハッシュ化せずにそのまま返すこともできる
    if settings.DEBUG and settings.PROJECT_NAME == "COLLABOAGAMES0406 API":
        return password
    # ハッシュ化
    return pwd_context.hash(password)

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