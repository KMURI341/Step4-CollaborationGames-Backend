# app/api/users/router.py
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...core.security import get_password_hash
from ..auth.jwt import get_current_user
from .models import User
from .schemas import UserCreate, UserResponse, UserUpdate

router = APIRouter()

@router.get("/me", response_model=UserResponse)
def get_current_user_info(
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    現在のログインユーザーの情報を取得
    """
    # カテゴリーをリストに変換
    categories = current_user.get_categories_list()
    
    # レスポンスを構築
    return {
        "id": current_user.user_id,
        "name": current_user.name,
        "categories": categories,
        "points": current_user.point_total,
        "created_at": current_user.created_at
    }

@router.put("/me", response_model=UserResponse)
def update_user_info(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Any:
    """
    現在のログインユーザーの情報を更新
    """
    # パスワードの確認（入力されている場合）
    if user_data.password and user_data.password != user_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="パスワードが一致しません",
        )
    
    # ユーザー名の変更がある場合、重複チェック
    if user_data.name and user_data.name != current_user.name:
        existing_user = db.query(User).filter(User.name == user_data.name).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="このユーザー名は既に使用されています",
            )
        current_user.name = user_data.name
    
    # パスワードの更新（入力されている場合）
    if user_data.password:
        current_user.password = get_password_hash(user_data.password)
    
    # カテゴリーの更新（入力されている場合）
    if user_data.categories is not None:
        current_user.set_categories_list(user_data.categories)
    
    # データベースを更新
    db.commit()
    db.refresh(current_user)
    
    # カテゴリーをリストに変換
    categories = current_user.get_categories_list()
    
    # レスポンスを構築
    return {
        "id": current_user.user_id,
        "name": current_user.name,
        "categories": categories,
        "points": current_user.point_total,
        "created_at": current_user.created_at
    }

@router.get("/categories", response_model=List[str])
def get_user_categories() -> List[str]:
    """
    利用可能なユーザーカテゴリーのリストを取得
    """
    # 利用可能なカテゴリーリスト
    categories = [
        "システム部",
        "経理部",
        "事業企画部",
        "デザイン部",
        "営業部",
        "アート",
        "音楽",
        "法務部",
        "知財部",
        "情セキ部",
    ]
    
    return categories