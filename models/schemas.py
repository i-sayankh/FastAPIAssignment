# models/schemas.py
from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"


class UserBase(BaseModel):
    username: str
    role: UserRole = UserRole.USER


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: str

    class Config:
        from_attributes = True


class ProjectBase(BaseModel):
    name: str
    description: str


class ProjectCreate(ProjectBase):
    pass


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True


class ErrorResponses(str, Enum):
    # Registration Errors
    USERNAME_EXISTS = "Username already exists"
    INVALID_USERNAME = "Username must be between 3 and 30 characters and contain only letters, numbers, and underscores"
    WEAK_PASSWORD = "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character"
    EMAIL_EXISTS = "Email already registered"
    INVALID_EMAIL = "Invalid email format"

    # Login Errors
    INVALID_CREDENTIALS = "Invalid username or password"
    ACCOUNT_LOCKED = "Account temporarily locked due to multiple failed attempts"
    ACCOUNT_INACTIVE = "Account is not activated"

    # Authentication Errors
    NOT_AUTHENTICATED = "Authentication required. Please log in to access this resource."
    TOKEN_EXPIRED = "Authentication token has expired. Please log in again."
    INVALID_TOKEN = "Invalid authentication token provided."

    # Authorization Errors
    NOT_ADMIN = "Access denied. Admin privileges required."
    NOT_CREATOR = "Access denied. Only project creators can modify this resource."
    INSUFFICIENT_PERMISSIONS = "Access denied. Insufficient permissions for this operation."

    PROJECT_NOT_FOUND = "Invalid Project Data Provided"
    INVALID_DATA = "Invalid Project Data Provided"
    SERVER_ERROR = "Internal Server Error"


class Token(BaseModel):
    access_token: str
    token_type: str
