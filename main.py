import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
from jose import JWTError, jwt

# Environment & constants
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecretkey")
ALGORITHM = "HS256"

# Database setup
client = AsyncIOMotorClient(MONGO_URL)
db = client["authdb"]
users = db["users"]

# Password hashing via bcrypt

def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

# OAuth2 scheme for JWT receiving
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# FastAPI app and CORS
app = FastAPI()
origins = [
    "http://orchestrator-ui:4000",
    "http://bruteforce-service:5002",
    "http://localhost:8000",
    "http://scanner-service:8001",
    "http://auth-service:8002",
    "http://sql-exploit-service:5003",
]  
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Helper: fetch user from DB
async def get_user(username: str):
    doc = await users.find_one({"username": username})
    if doc:
        return {"username": doc["username"], "hashed_password": doc["password"]}
    return None

# Authenticate user
async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

# JWT-based current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    creds_exc = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise creds_exc
    except JWTError:
        raise creds_exc
    user = await get_user(username)
    if user is None:
        raise creds_exc
    return user

# Routes
@app.post("/register", response_model=Token)
async def register(user: User):
    if await users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed = get_password_hash(user.password)
    await users.insert_one({"username": user.username, "password": hashed})
    token = jwt.encode({"sub": user.username}, JWT_SECRET, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    auth = await authenticate_user(form.username, form.password)
    if not auth:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = jwt.encode({"sub": form.username}, JWT_SECRET, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/health", dependencies=[Depends(get_current_user)])
async def health():
    return {"status": "ok"}

@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"]}