# app/users/models/models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime, CheckConstraint
from app.user_settings.models import Settings
from sqlalchemy.orm import relationship
from app.database.connection import Base
from app.helpers.time import utcnow


class User(Base):
    __tablename__ = "users"
    
    # username = Column(String, unique=True, index=True, nullable=False)
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    verification_code = Column(String, nullable=True)
    role = Column(String, default="user", nullable=False)
    gender = Column(String, default="unset", nullable=False)
    
    
    # Optional: Add more fields as needed
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    
    # Relationship with token blacklist
    blacklisted_tokens = relationship("TokenBlacklist", back_populates="user", cascade="all, delete-orphan")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")

    # Relationship with settings model 
    settings = relationship("Settings", back_populates="user", uselist=False)

    # Add check constraints for validation at database level
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'user')", name='check_role_values'),
        CheckConstraint("gender IN ('male', 'female', 'unset')", name='check_gender_values'),
    )

    def __repr__(self):
        return f"<User(id={self.id}, first_name='{self.first_name}', last_name='{self.last_name}', email='{self.email}')>"