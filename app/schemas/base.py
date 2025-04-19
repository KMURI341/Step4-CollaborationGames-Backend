# app/schemas/base.py
from pydantic import BaseModel, ConfigDict

class BaseSchemaModel(BaseModel):
    """
    デフォルトの設定を持つベーススキーマ
    - ORMモードを有効にし、データベースモデルとの互換性を確保
    - 追加のフィールドを許可
    """
    model_config = ConfigDict(
        from_attributes=True,  # ORMモードを有効化
        arbitrary_types_allowed=True,  # 任意の型を許可
        populate_by_name=True  # エイリアスフィールドの読み込みを許可
    )