# app/api/troubles/models.py
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

# 相対インポートに変更
from ...core.database import Base

class TroubleCategory(Base):
    __tablename__ = "trouble_categories"

    category_id = Column(Integer, primary_key=True, index=True)
    name = Column(Text, nullable=False)
    
    # リレーションシップ
    troubles = relationship("Trouble", back_populates="category")

class Trouble(Base):
    __tablename__ = "troubles"

    trouble_id = Column(Integer, primary_key=True, index=True)
    description = Column(Text, nullable=False)
    category_id = Column(Integer, ForeignKey("trouble_categories.category_id"), nullable=False)
    project_id = Column(Integer, ForeignKey("co_creation_projects.project_id"), nullable=False)
    creator_user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    status = Column(String, default="未解決")
    
    # リレーションシップ
    project = relationship("CoCreationProject", back_populates="troubles")
    creator = relationship("User", back_populates="troubles")
    category = relationship("TroubleCategory", back_populates="troubles")
    messages = relationship("Message", back_populates="trouble")
