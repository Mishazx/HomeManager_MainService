# auth_service/utils.py
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from .models import User
from app.db import SessionLocal
from sqlalchemy.orm import Session

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_admin_user(db: Session):
    admin_email = "admin@example.com"
    admin_username = "admin"
    admin_password = "adminpassword"  # Тут должен быть хеш пароля
    
    user = db.query(User).filter(User.email == admin_email).first()
    if not user:
        admin_user = User(
            email=admin_email,
            username=admin_username,
            hashed_password=admin_password,  
            is_superuser=True
        )
        db.add(admin_user)
        db.commit()


def verify_password(plain_password, password):
    hashed_password = get_password_hash(password)
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user
