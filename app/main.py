# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import sys
import os
from pathlib import Path

# プロジェクトのルートディレクトリをパスに追加
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

# コアの設定をインポート
from core.config import settings

# 認証関連のインポートを追加
from api.users.schemas import Token
from api.auth.router import login_for_access_token

# APIルーターのインポート
from api.troubles.router import router as troubles_router
from api.projects.router import router as projects_router
from api.users.router import router as users_router
from api.messages.router import router as messages_router
from api.auth.router import router as auth_router

try:
    from app.api.troubles.categories import router as trouble_categories_router
    from app.api.projects.categories import router as project_categories_router
    has_categories = True
except ImportError as e:
    print(f"カテゴリーモジュールのインポートに失敗しました: {e}")
    has_categories = False

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="コラボゲームズのバックエンドAPIサービス",
    version="0.1.0"
)

# CORSミドルウェアの設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ルーターの追加
app.include_router(troubles_router, prefix=f"{settings.API_V1_STR}/troubles", tags=["troubles"])
app.include_router(projects_router, prefix=f"{settings.API_V1_STR}/projects", tags=["projects"])
app.include_router(users_router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(messages_router, prefix=f"{settings.API_V1_STR}/messages", tags=["messages"])
app.include_router(auth_router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
# カテゴリールーターを追加
app.include_router(trouble_categories_router, prefix=f"{settings.API_V1_STR}/trouble-categories", tags=["trouble-categories"])
app.include_router(project_categories_router, prefix=f"{settings.API_V1_STR}/project-categories", tags=["project-categories"])

# ルートレベルに /token エンドポイントを追加
app.post("/token", response_model=Token)(login_for_access_token)

@app.get("/")
def read_root():
    return {"message": f"Welcome to {settings.PROJECT_NAME}"}

if __name__ == "__main__":
    uvicorn.run(
        app, 
        host=settings.HOST, 
        port=settings.PORT,
        reload=settings.DEBUG
    )