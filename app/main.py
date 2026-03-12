import secrets
import sqlite3
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pwdlib import PasswordHash
from pydantic import BaseModel

from app.db import get_conn

app = FastAPI()


SQL_COUNT = "SELECT COUNT(*) AS cnt FROM todos WHERE user_id = ?"
SQL_COUNT_COMPLETED = (
    "SELECT COUNT(*) AS cnt FROM todos WHERE user_id = ? AND completed = ?"
)

SQL_SELECT = """
SELECT id, title, description, completed, created_at, updated_at
FROM todos
WHERE user_id = ?
ORDER BY id DESC
LIMIT ? OFFSET ?
"""

SQL_SELECT_COMPLETED = """
SELECT id, title, description, completed, created_at, updated_at
FROM todos
WHERE user_id = ? AND completed = ?
ORDER BY id DESC
LIMIT ? OFFSET ?
"""


class Todos(BaseModel):
    title: str
    description: str | None = None
    completed: bool = False


class Reg(BaseModel):
    name: str
    email: str
    password: str


class Log(BaseModel):
    email: str
    password: str


def db_conn():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


password_hasher = PasswordHash.recommended()


def get_password_hash(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(plain_password: str, stored_hash: str) -> bool:
    return password_hasher.verify(plain_password, stored_hash)


def create_token() -> str:
    return secrets.token_urlsafe(32)


def get_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    return authorization.removeprefix("Bearer ").strip()


def get_current_user_id(
    conn: Annotated[sqlite3.Connection, Depends(db_conn)],
    authorization: Annotated[str | None, Header()] = None,
) -> int:
    token = get_bearer_token(authorization)

    row = conn.execute(
        """
        SELECT user_id
        FROM sessions
        WHERE token = ?
          AND (expires_at IS NULL OR expires_at > datetime('now'))
        """,
        (token,),
    ).fetchone()

    if row is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return row["user_id"]


CurrentUserId = Annotated[int, Depends(get_current_user_id)]


@app.post("/register")
def register(data: Reg, conn: Annotated[sqlite3.Connection, Depends(db_conn)]):
    password_hash = get_password_hash(data.password)

    try:
        cur = conn.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (data.name, data.email, password_hash),
        )
    except sqlite3.IntegrityError as err:
        raise HTTPException(status_code=409, detail="Email already registered") from err

    token = create_token()
    conn.execute(
        """
        INSERT INTO sessions (token, user_id, expires_at)
        VALUES (?, ?, datetime('now', '+7 days'))
        """,
        (token, cur.lastrowid),
    )

    return {"token": token}

@app.post("/login")
def login(data: Log, conn: Annotated[sqlite3.Connection, Depends(db_conn)]):
    user = conn.execute(
        "SELECT id, password_hash FROM users WHERE email = ?",
        (data.email,),
    ).fetchone()

    if user is None or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    #for check
    existing = conn.execute(
        """
        SELECT token
        FROM sessions
        WHERE user_id = ?
          AND (expires_at IS NULL OR expires_at > datetime('now'))
        """,
        (user["id"],),
    ).fetchone()

    if existing is not None:
        raise HTTPException(status_code=409, detail="Active session already exists. Logout first.")

    token = create_token()
    conn.execute(
        """
        INSERT INTO sessions (token, user_id, expires_at)
        VALUES (?, ?, datetime('now', '+7 days'))
        """,
        (token, user["id"]),
    )
    return {"token": token}

@app.get("/todos")
def list_todos(
    user_id: CurrentUserId,
    conn: Annotated[sqlite3.Connection, Depends(db_conn)],
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    completed: bool | None = Query(None),
):
    offset = (page - 1) * limit

    if completed is None:
        total = conn.execute(SQL_COUNT, (user_id,)).fetchone()["cnt"]
        rows = conn.execute(SQL_SELECT, (user_id, limit, offset)).fetchall()
    else:
        comp = int(completed)
        total = conn.execute(SQL_COUNT_COMPLETED, (user_id, comp)).fetchone()["cnt"]
        rows = conn.execute(
            SQL_SELECT_COMPLETED, (user_id, comp, limit, offset)
        ).fetchall()

    data = [
        {
            "id": r["id"],
            "title": r["title"],
            "description": r["description"],
            "completed": bool(r["completed"]),
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }
        for r in rows
    ]
    return {"data": data, "page": page, "limit": limit, "total": total}


@app.post("/logout")
def logout(
    conn: Annotated[sqlite3.Connection, Depends(db_conn)],
    authorization: Annotated[str | None, Header()] = None,
):
    token = get_bearer_token(authorization)
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return {"status": "ok"}


@app.get("/health")
def health(conn: Annotated[sqlite3.Connection, Depends(db_conn)]):
    conn.execute("SELECT 1;")
    return {"status": "ok"}
