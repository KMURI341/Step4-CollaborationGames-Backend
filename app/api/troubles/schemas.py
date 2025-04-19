# app/api/troubles/schemas.py
from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional

from ...schemas.base import BaseSchemaModel

class TroubleCategoryBase(BaseSchemaModel):
    name: str = Field(..., min_length=1, description="カテゴリー名")

class TroubleCategoryCreate(TroubleCategoryBase):
    pass

class TroubleCategoryResponse(TroubleCategoryBase):
    category_id: int

class TroubleBase(BaseSchemaModel):
    description: str = Field(..., min_length=10, max_length=1000, description="お困りごとの詳細説明")
    category_id: int = Field(..., description="お困りごとのカテゴリーID")

class TroubleCreate(TroubleBase):
    project_id: int = Field(..., description="関連するプロジェクトID")
    status: Optional[str] = Field("未解決", description="お困りごとの状態 ('未解決' または '解決')")

class TroubleUpdate(BaseSchemaModel):
    description: Optional[str] = Field(None, min_length=10, max_length=1000)
    category_id: Optional[int] = Field(None)
    status: Optional[str] = Field(None)

class TroubleResponse(BaseSchemaModel):
    trouble_id: int
    description: str
    category_id: int
    project_id: int
    project_title: str
    creator_user_id: int
    creator_name: str
    created_at: datetime
    status: str
    comments: int = 0

class TroubleDetailResponse(TroubleResponse):
    # メッセージ関連の情報を追加する場合
    # messages: List[MessageResponse] = []
    pass

class TroublesListResponse(BaseSchemaModel):
    troubles: List[TroubleResponse]
    total: int