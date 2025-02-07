from fastapi import Depends, HTTPException, status
from jose import jwt, JWTError
from datetime import datetime, timedelta
from database.database import user_collection
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from models.user import Login
from fastapi import APIRouter, HTTPException, Depends, UploadFile, Request, Form, File, status


ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# def create_access_token(data: dict, expires_delta: timedelta = None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire, "email": data.get("email")})  # Add email to token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


    
    
    
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# async def get_current_user(token: str = Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#     except JWTError:
#         raise credentials_exception
#     user = collection_name.find_one({"name": username})
#     if user is None:
#         raise credentials_exception
#     return user

def get_current_user(request: Request):
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Decode the token to get the user_id
    try:
        payload = jwt.decode(token, Process.env["SECRET_KEY"], algorithms=[Process.env["JWT_ALGORITHM"]])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        # Check if the user_id matches any user in the database
        user = user_collection.find_one({"_id": ObjectId(user_id)})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Check if the token stored in the user's document matches the token from the request
        if user.get("token") != token:
            raise HTTPException(status_code=401, detail="Invalid token")

        user["_id"] = str(user["_id"])
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")