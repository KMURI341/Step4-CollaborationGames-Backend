# app/core/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from typing import Dict, Any

# 相対インポートに変更
from .config import settings

# データベース接続設定
def get_db_connect_args() -> Dict[str, Any]:
    """データベース接続引数を取得"""
    connect_args = {}
    
    # Azure MySQLの場合のSSL設定
    if settings.USE_AZURE:
        ssl_mode = settings.AZURE_MYSQL_SSL_MODE.lower()
        if ssl_mode == "require":
            # SSL 証明書のパスを指定
            connect_args["ssl"] = {
                "ssl_ca": r"C:\Users\mmkji\.ssl\DigiCertGlobalRootCA.crt.pem"
            }
    elif "sqlite" in settings.SQLALCHEMY_DATABASE_URL:
        # SQLiteの場合は同時接続チェックをオフ
        connect_args["check_same_thread"] = False
    
    return connect_args

# エンジンの作成
engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URL,
    connect_args=get_db_connect_args(),
    pool_pre_ping=True,  # 接続が生きているか確認
    poolclass=NullPool if settings.USE_AZURE else None,  # Azureの場合のみNullPoolを使用
    echo=settings.DEBUG  # デバッグモードの場合、SQLクエリをコンソールに表示
)

# セッションファクトリーの作成
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ベースクラスの作成
Base = declarative_base()

# データベースセッションの依存性注入
def get_db():
    """
    依存性注入用のデータベースセッション取得関数
    FastAPIのDependsで使用する
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()