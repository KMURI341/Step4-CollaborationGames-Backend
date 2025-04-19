# app/api/troubles/router.py
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime

from ...core.database import get_db
from ..auth.jwt import get_current_user
from ..users.models import User
from ..projects.models import CoCreationProject
from .models import Trouble, TroubleCategory

from . import schemas

router = APIRouter()

@router.post("/", response_model=schemas.TroubleResponse)
def create_trouble(
    trouble: schemas.TroubleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # プロジェクトが存在するか確認
    project = db.query(CoCreationProject).filter(CoCreationProject.project_id == trouble.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="プロジェクトが見つかりません")
    
    # お困りごと作成
    new_trouble = Trouble(
        description=trouble.description,
        project_id=trouble.project_id,
        category_id=trouble.category_id,
        creator_user_id=current_user.user_id,
        created_at=datetime.now(),
        status="未解決"
    )
    
    db.add(new_trouble)
    db.commit()
    db.refresh(new_trouble)
    
    return schemas.TroubleResponse(
        trouble_id=new_trouble.trouble_id,
        description=new_trouble.description,
        category_id=new_trouble.category_id,
        project_id=new_trouble.project_id,
        project_title=project.title,
        creator_user_id=new_trouble.creator_user_id,
        creator_name=current_user.name,
        created_at=new_trouble.created_at,
        status=new_trouble.status,
        comments=0  # 新規作成時はコメント数0
    )

# 簡易版のお困りごと作成エンドポイント
@router.post("/simple", status_code=status.HTTP_201_CREATED)
def create_trouble_simple(
    project_id: int,
    category_id: int,
    description: str,
    status: Optional[str] = "未解決",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    スキーマ検証をバイパスする簡易版のお困りごと作成エンドポイント
    """
    # プロジェクトが存在するか確認
    project = db.query(CoCreationProject).filter(CoCreationProject.project_id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="プロジェクトが見つかりません")
    
    # お困りごと作成
    new_trouble = Trouble(
        description=description,
        project_id=project_id,
        category_id=category_id,
        creator_user_id=current_user.user_id,
        created_at=datetime.now(),
        status=status
    )
    
    db.add(new_trouble)
    db.commit()
    db.refresh(new_trouble)
    
    return {
        "trouble_id": new_trouble.trouble_id,
        "message": "お困りごとを登録しました"
    }

@router.get("/", response_model=schemas.TroublesListResponse)
def get_troubles(
    project_id: int = Query(None, description="特定のプロジェクトのお困りごとを取得"),
    category_id: Optional[int] = Query(None, description="カテゴリでフィルタリング"),
    status: Optional[str] = Query(None, description="状態でフィルタリング"),
    skip: int = 0,
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # クエリ作成
    query = db.query(Trouble)
    
    # プロジェクトIDによるフィルタリング
    if project_id:
        query = query.filter(Trouble.project_id == project_id)
    
    # カテゴリによるフィルタリング
    if category_id:
        query = query.filter(Trouble.category_id == category_id)
    
    # 状態によるフィルタリング
    if status:
        query = query.filter(Trouble.status == status)
    
    # 作成日時で降順ソート
    query = query.order_by(Trouble.created_at.desc())
    
    # 総数取得
    total = query.count()
    
    # ページネーション適用
    troubles = query.offset(skip).limit(limit).all()
    
    # レスポンス形式に変換
    trouble_list = []
    for trouble in troubles:
        # プロジェクト情報取得
        project = db.query(CoCreationProject).filter(CoCreationProject.project_id == trouble.project_id).first()
        
        # 作成者情報取得
        creator = db.query(User).filter(User.user_id == trouble.creator_user_id).first()
        
        # コメント数取得（メッセージとして扱う）
        from ..messages.models import Message
        comments_count = db.query(Message).filter(Message.trouble_id == trouble.trouble_id).count()
        
        trouble_list.append(schemas.TroubleResponse(
            trouble_id=trouble.trouble_id,
            description=trouble.description,
            category_id=trouble.category_id,
            project_id=trouble.project_id,
            project_title=project.title if project else "Unknown Project",
            creator_user_id=trouble.creator_user_id,
            creator_name=creator.name if creator else "Unknown User",
            created_at=trouble.created_at,
            status=trouble.status,
            comments=comments_count
        ))
    
    return schemas.TroublesListResponse(
        troubles=trouble_list,
        total=total
    )

@router.get("/{trouble_id}", response_model=schemas.TroubleDetailResponse)
def get_trouble_detail(
    trouble_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # お困りごと取得
    trouble = db.query(Trouble).filter(Trouble.trouble_id == trouble_id).first()
    if not trouble:
        raise HTTPException(status_code=404, detail="お困りごとが見つかりません")
    
    # プロジェクト情報取得
    project = db.query(CoCreationProject).filter(CoCreationProject.project_id == trouble.project_id).first()
    
    # 作成者情報取得
    creator = db.query(User).filter(User.user_id == trouble.creator_user_id).first()
    
    # コメント数取得（メッセージとして扱う）
    from ..messages.models import Message
    comments_count = db.query(Message).filter(Message.trouble_id == trouble.trouble_id).count()
    
    return schemas.TroubleDetailResponse(
        trouble_id=trouble.trouble_id,
        description=trouble.description,
        category_id=trouble.category_id,
        project_id=trouble.project_id,
        project_title=project.title if project else "Unknown Project",
        creator_user_id=trouble.creator_user_id,
        creator_name=creator.name if creator else "Unknown User",
        created_at=trouble.created_at,
        status=trouble.status,
        comments=comments_count
    )

@router.put("/{trouble_id}", response_model=schemas.TroubleResponse)
def update_trouble(
    trouble_id: int,
    trouble_update: schemas.TroubleUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # お困りごと取得
    trouble = db.query(Trouble).filter(Trouble.trouble_id == trouble_id).first()
    if not trouble:
        raise HTTPException(status_code=404, detail="お困りごとが見つかりません")
    
    # 作成者のみ更新可能
    if trouble.creator_user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="自分のお困りごとのみ更新できます")
    
    # 更新処理
    if trouble_update.description is not None:
        trouble.description = trouble_update.description
    if trouble_update.category_id is not None:
        trouble.category_id = trouble_update.category_id
    if trouble_update.status is not None:
        if trouble_update.status not in ["未解決", "解決"]:
            raise HTTPException(status_code=400, detail="ステータスは「未解決」または「解決」のみ設定可能です")
        trouble.status = trouble_update.status
    
    db.commit()
    db.refresh(trouble)
    
    # プロジェクト情報取得
    project = db.query(CoCreationProject).filter(CoCreationProject.project_id == trouble.project_id).first()
    
    return schemas.TroubleResponse(
        trouble_id=trouble.trouble_id,
        description=trouble.description,
        category_id=trouble.category_id,
        project_id=trouble.project_id,
        project_title=project.title if project else "Unknown Project",
        creator_user_id=trouble.creator_user_id,
        creator_name=current_user.name,
        created_at=trouble.created_at,
        status=trouble.status,
        comments=0  # 実際のコメント数は再取得する必要がある
    )

@router.delete("/{trouble_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_trouble(
    trouble_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # お困りごと取得
    trouble = db.query(Trouble).filter(Trouble.trouble_id == trouble_id).first()
    if not trouble:
        raise HTTPException(status_code=404, detail="お困りごとが見つかりません")
    
    # 作成者のみ削除可能
    if trouble.creator_user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="自分のお困りごとのみ削除できます")
    
    # 削除
    db.delete(trouble)
    db.commit()
    
    return None

@router.get("/categories", response_model=List[schemas.TroubleCategoryResponse])
def get_trouble_categories(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # データベースからカテゴリを取得
    categories = db.query(TroubleCategory).all()
    
    # カテゴリがない場合は初期データを挿入
    if not categories:
        default_categories = [
            "UI/UXデザイン", "コンテンツ制作", "モバイル開発", "技術相談", "マーケティング"
        ]
        
        for name in default_categories:
            category = TroubleCategory(name=name)
            db.add(category)
        
        db.commit()
        categories = db.query(TroubleCategory).all()
    
    return [
        schemas.TroubleCategoryResponse(
            category_id=category.category_id,
            name=category.name
        ) for category in categories
    ]