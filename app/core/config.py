# app/core/config.py
from typing import List
import os
import re
from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

# .envファイルを読み込む
load_dotenv()

# 環境変数のパース問題を修正するヘルパー関数
def parse_int_env(env_name, default_value):
    try:
        value_str = os.getenv(env_name, str(default_value))
        # 数値部分のみを抽出
        match = re.match(r'\d+', value_str)
        if match:
            return int(match.group(0))
        return default_value
    except (ValueError, AttributeError):
        print(f"Warning: {env_name} could not be parsed, using default: {default_value}")
        return default_value

class Settings(BaseSettings):
    # プロジェクト設定
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "CollaboGames")
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    API_V1_STR: str = os.getenv("API_V1_STR", "/api/v1")
    
    # サーバー設定
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

    # Azure MySQL設定
    AZURE_MYSQL_HOST: str = os.getenv("AZURE_MYSQL_HOST", "")
    AZURE_MYSQL_USER: str = os.getenv("AZURE_MYSQL_USER", "")
    AZURE_MYSQL_PASSWORD: str = os.getenv("AZURE_MYSQL_PASSWORD", "")
    AZURE_MYSQL_DATABASE: str = os.getenv("AZURE_MYSQL_DATABASE", "")
    AZURE_MYSQL_PORT: str = os.getenv("AZURE_MYSQL_PORT", "3306")
    AZURE_MYSQL_SSL_MODE: str = os.getenv("AZURE_MYSQL_SSL_MODE", "")
    USE_AZURE: bool = os.getenv("USE_AZURE", "False").lower() == "true"
    
    # 通常のデータベース設定
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_USER: str = os.getenv("DB_USER", "root")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")
    DB_NAME: str = os.getenv("DB_NAME", "collabo_db")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./test.db")

    # セキュリティ設定
    SECRET_KEY: str = os.getenv("SECRET_KEY", "fallback_secret_key_please_change_in_production")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

    # CORS設定 - 環境変数から読み込むように修正
    CORS_ORIGINS_STR: str = os.getenv("CORS_ORIGINS_STR", "http://localhost:3000")
    ALLOWED_HOSTS: list = ["*"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # 追加の変数を無視

    # プロパティとしてCORS_ORIGINSを実装
    @property
    def CORS_ORIGINS(self) -> List[str]:
        # アスタリスクが含まれている場合は全てのオリジンを許可
        if "*" in self.CORS_ORIGINS_STR:
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS_STR.split(",")]
    
    # データベースURLを動的に生成
    @property
    def SQLALCHEMY_DATABASE_URL(self) -> str:
        if self.USE_AZURE:
            # Azure MySQL用の接続URL
            return f"mysql+pymysql://{self.AZURE_MYSQL_USER}:{self.AZURE_MYSQL_PASSWORD}@{self.AZURE_MYSQL_HOST}:{self.AZURE_MYSQL_PORT}/{self.AZURE_MYSQL_DATABASE}"
        else:
            # 通常のデータベース接続URL
            return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

# グローバル設定インスタンスの作成
settings = Settings()