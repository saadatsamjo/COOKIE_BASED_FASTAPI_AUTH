# app/authentication/models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from app.database.connection import Base
from sqlalchemy.orm import relationship
from app.helpers.time import utcnow



class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    blacklisted_at = Column(DateTime(timezone=True), default=lambda: utcnow())
    expires_at = Column(DateTime(timezone=True), default=lambda: utcnow())
    
    user = relationship("User", back_populates="blacklisted_tokens")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime(timezone=True), default=lambda: utcnow() + timedelta(hours=1))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    used = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="password_reset_tokens")