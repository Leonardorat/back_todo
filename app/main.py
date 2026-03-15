import secrets
import sqlite3
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Path,
    Query,
    Response,
    status,
)
from pwdlib import PasswordHash
from pydantic import BaseModel, Field

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


class TodoIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    completed: bool = False


class Reg(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)


class Log(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)


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


def todo_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "completed": bool(row["completed"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def get_todo_row(conn: sqlite3.Connection, todo_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT id, user_id, title, description, completed, created_at, updated_at
        FROM todos
        WHERE id = ?
        """,
        (todo_id,),
    ).fetchone()


def get_owned_todo_or_error(
    conn: sqlite3.Connection,
    todo_id: int,
    user_id: int,
) -> sqlite3.Row:
    row = get_todo_row(conn, todo_id)

    if row is None:
        raise HTTPException(status_code=404, detail="Todo not found")

    if row["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    return row


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
        raise HTTPException(
            status_code=409,
            detail="Active session already exists. Logout first.",
        )

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

    data = [todo_to_dict(r) for r in rows]
    return {"data": data, "page": page, "limit": limit, "total": total}


@app.post("/todos", status_code=status.HTTP_201_CREATED)
def create_todo(
    data: TodoIn,
    user_id: CurrentUserId,
    conn: Annotated[sqlite3.Connection, Depends(db_conn)],
):
    cur = conn.execute(
        """
        INSERT INTO todos (user_id, title, description, completed)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, data.title, data.description, int(data.completed)),
    )

    row = get_todo_row(conn, cur.lastrowid)
    return todo_to_dict(row)


@app.put("/todos/{todo_id}")
def update_todo(
    data: TodoIn,
    user_id: CurrentUserId,
    conn: Annotated[sqlite3.Connection, Depends(db_conn)],
    todo_id: int = Path(..., ge=1),
):
    get_owned_todo_or_error(conn, todo_id, user_id)

    conn.execute(
        """
        UPDATE todos
        SET title = ?, description = ?, completed = ?
        WHERE id = ?
        """,
        (data.title, data.description, int(data.completed), todo_id),
    )

    row = get_todo_row(conn, todo_id)
    return todo_to_dict(row)


@app.delete("/todos/{todo_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_todo(
    user_id: CurrentUserId,
    conn: Annotated[sqlite3.Connection, Depends(db_conn)],
    todo_id: int = Path(..., ge=1),
):
    get_owned_todo_or_error(conn, todo_id, user_id)

    conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
