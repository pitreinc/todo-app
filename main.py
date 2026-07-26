from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List

app = FastAPI()

# Security key (same as before)
SECRET_KEY = os.getenv("SECRET_KEY", "william-todo-secret-2026")

# Database connection
DATABASE_URL = os.getenv("DATABASE_URL")

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            text TEXT NOT NULL,
            completed BOOLEAN DEFAULT FALSE
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

# Initialize table on startup
try:
    init_db()
except Exception as e:
    print("Database init error:", e)

def verify_key(x_api_key: str = Header(None)):
    if x_api_key != SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

class TodoCreate(BaseModel):
    text: str

class Todo(BaseModel):
    id: int
    text: str
    completed: bool

@app.get("/todos", response_model=List[Todo], dependencies=[Depends(verify_key)])
def list_todos():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, text, completed FROM todos ORDER BY id")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

@app.post("/todos", response_model=Todo, dependencies=[Depends(verify_key)])
def create_todo(todo: TodoCreate):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO todos (text) VALUES (%s) RETURNING id, text, completed",
        (todo.text,)
    )
    new_todo = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return new_todo

@app.put("/todos/{todo_id}", dependencies=[Depends(verify_key)])
def update_todo(todo_id: int, completed: bool):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE todos SET completed = %s WHERE id = %s",
        (completed, todo_id)
    )
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Todo updated"}

@app.delete("/todos/{todo_id}", dependencies=[Depends(verify_key)])
def delete_todo(todo_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM todos WHERE id = %s", (todo_id,))
    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Todo deleted"}

@app.get("/")
def read_index():
	return FileResponse("index.html")
