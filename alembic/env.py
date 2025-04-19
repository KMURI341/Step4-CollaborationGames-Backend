from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys

# プロジェクトのルートディレクトリをパスに追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# アプリケーションの設定とモデルをインポート
from app.core.database import Base
from app.core.config import settings

# Alembicの設定ファイルからログ設定を読み込む
config = context.config

# この行を追加して、環境変数からデータベースURLを取得
config.set_main_option('sqlalchemy.url', settings.DATABASE_URL)

# Alembicの設定ファイルからロガーの設定を読み込む
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# マイグレーションの対象となるメタデータを設定
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """オフラインモードでマイグレーションを実行"""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """オンラインモードでマイグレーションを実行"""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()