# app/api/messages/schemas.py
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

from ...schemas.base import BaseSchemaModel

class MessageBase(BaseSchemaModel):
    content: str = Field(..., min_length=1, description="メッセージの内容")

class MessageCreate(MessageBase):
    trouble_id: int = Field(..., description="関連するお困りごとID")

class MessageResponse(MessageBase):
    id: int
    user_id: int
    user_name: str
    trouble_id: int
    created_at: datetime

class MessagesListResponse(BaseSchemaModel):
    messages: List[MessageResponse]
    total: int