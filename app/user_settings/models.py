# app/user_settings/models/models.py

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from app.database.connection import Base


class Settings(Base):
    __tablename__ = "user_settings"

    settings_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    display_name = Column(String, nullable=True)
    profile_picture = Column(String, nullable=True)
    cover_picture = Column(String, nullable=True)
    bio = Column(String, nullable=True)
    theme=Column(String, default="light", nullable=False)
    notifications = Column(Boolean, default=True)
    language = Column(String, default="en")

    user = relationship("User", back_populates="settings")