from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, or_
from typing import Optional, cast
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
import httpx
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from datetime import datetime, timedelta

import bcrypt
if not hasattr(bcrypt, '__about__'):
    bcrypt.__about__ = type('about', (), {'__version__': bcrypt.__version__})()

from dotenv import load_dotenv
load_dotenv()

import logging
logging.basicConfig(level=logging.INFO)

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT settings
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    phone = Column(String, nullable=True)
    cpf = Column(String, nullable=True)
    location = Column(String, nullable=True)

Base.metadata.create_all(bind=engine)

class RegisterRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: EmailStr
    password: str
    phone: Optional[str] = None
    cpf: str
    location: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChatRequest(BaseModel):
    message: str


class UpdateUserRequest(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    current_email: Optional[EmailStr] = None
    new_email: Optional[EmailStr] = None
    phone: Optional[str] = None
    cpf: Optional[str] = None
    location: Optional[str] = None
    password: Optional[str] = None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post('/api/register')
async def register(request: RegisterRequest, db: Session = Depends(get_db)):
    # logging.error(f"Received registration request for email: {request.email}")
    # logging.error(f"{request.email} {request.password}")
    email = request.email.strip()
    password = request.password
    first_name = request.first_name if hasattr(request, 'first_name') else None
    last_name = request.last_name if hasattr(request, 'last_name') else None
    phone = request.phone if hasattr(request, 'phone') else None
    raw_cpf = request.cpf.strip()
    location = request.location if hasattr(request, 'location') else None

    # Normalize CPF: keep only digits
    cpf = ''.join(ch for ch in raw_cpf if ch.isdigit())
    if len(cpf) != 11:
        raise HTTPException(status_code=400, detail="CPF must contain exactly 11 digits")
    
    
    # Check if user already exists by email or CPF
    existing_user = db.query(User.id, User.email, User.cpf).filter(or_(User.email == email, User.cpf == cpf)).first()
    if existing_user:
        if existing_user.email == email:
            raise HTTPException(status_code=409, detail="Email already registered. Sign in!")
        if existing_user.cpf == cpf:
            raise HTTPException(status_code=409, detail="CPF already registered. Sign in!")
    
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    # Check password length for bcrypt limit (72 bytes)
    if len(password.encode('utf-8')) > 72:
        raise HTTPException(status_code=400, detail="Password must be 72 bytes or less")
    
    # Hash password and create user
    hashed_password = get_password_hash(password)
    db_user = User(first_name=first_name, last_name=last_name, email=email, hashed_password=hashed_password, phone=phone, cpf=cpf, location=location)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Generate token (assuming registration returns a token)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": email}, expires_delta=access_token_expires
    )
    
    return {"message": "User registered successfully", "token": access_token, "email": email}

@app.post('/api/login')
async def login(request: LoginRequest, db: Session = Depends(get_db)):
    email = request.email
    password = request.password
    
    db_user: Optional[User] = db.query(User).filter(User.email == email).first()
    if not db_user or not verify_password(password, hashed_password=str(db_user.hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": email}, expires_delta=access_token_expires)
    expires_at = datetime.utcnow() + access_token_expires
    logging.info(f"User {email} logged in successfully. Token expires at {expires_at.isoformat()}")
    return {"message": "Successfully logged in", "access_token": access_token, "token_type": "bearer", "expires_at": expires_at.isoformat()}


class RecoverRequest(BaseModel):
    email: EmailStr

# method to receive request and save in the user info, method put
@app.put('/api/user/update/{user_id}')
async def update_user(user_id: int, request: UpdateUserRequest, db: Session = Depends(get_db)):
    db_user: Optional[User] = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user = cast(User, db_user)

    # Optional concurrency check: ensure current_email matches
    if request.current_email and request.current_email != db_user.email:
        raise HTTPException(status_code=409, detail="Current email does not match user")

    # Update email if provided and not taken
    if request.new_email and request.new_email != db_user.email:
        normalized_new_email = request.new_email.strip()
        existing = db.query(User).filter(User.email == normalized_new_email, User.id != db_user.id).first()
        if existing:
            raise HTTPException(status_code=409, detail="Email already registered")
        db_user.email = normalized_new_email  # type: ignore[assignment]

    # Update CPF if provided and valid and not taken by another user
    if request.cpf is not None:
        normalized_cpf = ''.join(ch for ch in request.cpf if ch.isdigit())
        if len(normalized_cpf) != 11:
            raise HTTPException(status_code=400, detail="CPF must contain exactly 11 digits")
        existing_cpf = db.query(User).filter(User.cpf == normalized_cpf, User.id != db_user.id).first()
        if existing_cpf:
            raise HTTPException(status_code=409, detail="CPF already registered")
        db_user.cpf = normalized_cpf  # type: ignore[assignment]

    # Other optional fields
    if request.phone is not None:
        db_user.phone = request.phone.strip() if isinstance(request.phone, str) else request.phone  # type: ignore[assignment]
    if request.location is not None:
        db_user.location = request.location.strip() if isinstance(request.location, str) else request.location  # type: ignore[assignment]

    # First and last names
    if request.first_name is not None:
        db_user.first_name = request.first_name.strip() if isinstance(request.first_name, str) else request.first_name  # type: ignore[assignment]
    if request.last_name is not None:
        db_user.last_name = request.last_name.strip() if isinstance(request.last_name, str) else request.last_name  # type: ignore[assignment]

    # Update password if provided
    if request.password:
        if len(request.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        if len(request.password.encode('utf-8')) > 72:
            raise HTTPException(status_code=400, detail="Password must be 72 bytes or less")
        db_user.hashed_password = get_password_hash(request.password)  # type: ignore[assignment]

    db.commit()
    db.refresh(db_user)

    return {"message": "User updated successfully", "email": db_user.email, "cpf": db_user.cpf}


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user: Optional[User] = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


@app.get('/api/profile')
async def profile(current_user: User = Depends(get_current_user)):
    logging.info(f"User {current_user.email} accessed their profile")
    return {
        "id": current_user.id,
        "first_name": current_user.first_name if hasattr(current_user, 'first_name') else None,
        "last_name": current_user.last_name if hasattr(current_user, 'last_name') else None,
        "email": current_user.email,
        "phone": current_user.phone,
        "cpf": current_user.cpf,
        "location": current_user.location,
    }


@app.post('/api/recoverpassword')
async def recover_password(request: RecoverRequest, db: Session = Depends(get_db)):
    """Generate a short-lived password recovery token.

    NOTE: In production you should send this token via email and not return it in the API response.
    """
    email = request.email
    db_user = db.query(User).filter(User.email == email).first()
    # Do not reveal whether the account exists to the caller in production;
    # return a generic success message. For testing we return the token when the user exists.
    if not db_user:
        return {"message": "If an account with that email exists, a recovery email has been sent."}

    recover_expires = timedelta(minutes=15)
    recovery_token = create_access_token(data={"sub": email, "scope": "password_recovery"}, expires_delta=recover_expires)
    expires_at = datetime.utcnow() + recover_expires
    logging.info(f"Generated password recovery token for {email}, expires at {expires_at.isoformat()}")

    # For development/testing return token; in production send it by email instead.
    return {
        "message": "Password recovery token generated. (In production this would be emailed)",
        "recovery_token": recovery_token,
        "expires_at": expires_at.isoformat(),
    }


@app.post('/api/chat')
async def chat_with_deepseek(request: ChatRequest):
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="DeepSeek API key is not configured")

    payload = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "user", "content": request.message}
        ],
        "stream": False,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post("https://api.deepseek.com/v1/chat/completions", json=payload, headers=headers)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"DeepSeek request failed: {exc}")

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    data = resp.json()
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    return {"reply": content}

if __name__ == '__main__':
    uvicorn.run(app, host='localhost', port=8000)
