# app/api/troubles/categories.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from ...core.database import get_db
from ..auth.jwt import get_current_user
from ..users.models import User
from .models import TroubleCategory
from .schemas import TroubleCategoryResponse, TroubleCategoryCreate

router = APIRouter()

@router.get("", response_model=List[TroubleCategoryResponse])
def get_categories(db: Session = Depends(get_db)):
    """
    すべてのお困りごとカテゴリーを取得します。
    """
    categories = db.query(TroubleCategory).all()
    
    return [
        TroubleCategoryResponse(
            category_id=category.category_id,
            name=category.name
        ) for category in categories
    ]

@router.get("/{category_id}", response_model=TroubleCategoryResponse)
def get_category(category_id: int, db: Session = Depends(get_db)):
    """
    特定のカテゴリーを取得します。
    """
    category = db.query(TroubleCategory).filter(TroubleCategory.category_id == category_id).first()
    if not category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="カテゴリーが見つかりません"
        )
    return TroubleCategoryResponse(
        category_id=category.category_id,
        name=category.name
    )

@router.post("", response_model=TroubleCategoryResponse, status_code=status.HTTP_201_CREATED)
def create_category(
    category: TroubleCategoryCreate, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    新しいカテゴリーを作成します。（管理者専用）
    """
    # 同名のカテゴリーが存在するか確認
    existing_category = db.query(TroubleCategory).filter(
        TroubleCategory.name == category.name
    ).first()
    
    if existing_category:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="同じ名前のカテゴリーが既に存在します"
        )
    
    # 新しいカテゴリーを作成
    db_category = TroubleCategory(name=category.name)
    db.add(db_category)
    db.commit()
    db.refresh(db_category)
    
    return TroubleCategoryResponse(
        category_id=db_category.category_id,
        name=db_category.name
    )

@router.put("/{category_id}", response_model=TroubleCategoryResponse)
def update_category(
    category_id: int,
    category: TroubleCategoryCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    カテゴリーを更新します。（管理者専用）
    """
    # 更新対象のカテゴリーを取得
    db_category = db.query(TroubleCategory).filter(
        TroubleCategory.category_id == category_id
    ).first()
    
    if not db_category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="カテゴリーが見つかりません"
        )
    
    # 同名の別カテゴリーが存在するか確認
    existing_category = db.query(TroubleCategory).filter(
        TroubleCategory.name == category.name,
        TroubleCategory.category_id != category_id
    ).first()
    
    if existing_category:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="同じ名前のカテゴリーが既に存在します"
        )
    
    # カテゴリー名を更新
    db_category.name = category.name
    db.commit()
    db.refresh(db_category)
    
    return TroubleCategoryResponse(
        category_id=db_category.category_id,
        name=db_category.name
    )

@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(
    category_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    カテゴリーを削除します。（管理者専用）
    """
    # 削除対象のカテゴリーを取得
    db_category = db.query(TroubleCategory).filter(
        TroubleCategory.category_id == category_id
    ).first()
    
    if not db_category:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="カテゴリーが見つかりません"
        )
    
    # このカテゴリーに関連付けられたお困りごとの処理
    # 例: 関連お困りごとのカテゴリーをnullに設定する
    # db.query(Trouble).filter(Trouble.category_id == category_id).update(
    #     {"category_id": None}
    # )
    
    # カテゴリーを削除
    db.delete(db_category)
    db.commit()
    
    return None