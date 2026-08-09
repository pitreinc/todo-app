from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt

app = FastAPI()

SECRET_KEY = os.getenv("SECRET_KEY", "william-todo-secret-2026")
DATABASE_URL = os.getenv("DATABASE_URL")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Todos table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            text TEXT NOT NULL,
            completed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Add user_id column if it does not exist yet
    cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'todos' AND column_name = 'user_id'
            ) THEN
                ALTER TABLE todos ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
            END IF;
        END $$;
    """)

    conn.commit()
    cur.close()
    conn.close()

try:
    init_db()
except Exception as e:
    print("Database init error:", e)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_id = int(user_id)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TodoCreate(BaseModel):
    text: str

class Todo(BaseModel):
    id: int
    text: str
    completed: bool

@app.post("/register", response_model=Token)
def register(user: UserCreate):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (user.email,))
    if cur.fetchone():
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = get_password_hash(user.password)
    cur.execute(
        "INSERT INTO users (email, hashed_password) VALUES (%s, %s) RETURNING id",
        (user.email, hashed)
    )
    new_user = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    access_token = create_access_token(data={"sub": new_user["id"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login", response_model=Token)
def login(user: UserLogin):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, hashed_password FROM users WHERE email = %s", (user.email,))
    db_user = cur.fetchone()
    cur.close()
    conn.close()

    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": db_user["id"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/todos", response_model=List[Todo])
def list_todos(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, text, completed FROM todos WHERE user_id = %s ORDER BY id",
        (current_user["id"],)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

@app.post("/todos", response_model=Todo)
def create_todo(todo: TodoCreate, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO todos (user_id, text) VALUES (%s, %s) RETURNING id, text, completed",
        (current_user["id"], todo.text)
    )
    new_todo = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return new_todo

@app.put("/todos/{todo_id}")
def update_todo(todo_id: int, completed: bool, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE todos SET completed = %s WHERE id = %s AND user_id = %s",
        (completed, todo_id, current_user["id"])
    )
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Todo not found")
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Todo updated"}

@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM todos WHERE id = %s AND user_id = %s",
        (todo_id, current_user["id"])
    )
    if cur.rowcount == 0:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Todo not found")
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Todo deleted"}

@app.get("/")
def read_index():
    return FileResponse("index.html")
