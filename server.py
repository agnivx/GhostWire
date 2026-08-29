"""
GhostWire - End-to-End Encrypted P2P Messaging Platform
Features: Real-time WebSockets, REST API, WebAuthn Security, E2EE Prekey Bundles,
          SQLite Persistence, Dedicated Real-time Moderator Operations Suite
"""

import asyncio
import hashlib
import json
import logging
import os
import secrets
import sys
import time
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Header,
    Query,
    Response,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import DateTime, Text, inspect, or_, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import Field, SQLModel, select

# WebAuthn & Base64 Helpers
try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers import (
        base64url_to_bytes,
        bytes_to_base64url,
        parse_authentication_credential_json,
        parse_registration_credential_json,
    )
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False
    import base64
    def bytes_to_base64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ghostwire")

# --- Settings & Constants ---
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production-123456789")
MODERATOR_KEY_SALT = b"e2ee_chat_mod_salt_2026"
# Cryptographically hashed moderator key: PBKDF2-HMAC-SHA256 (200,000 iterations)
# Raw key is never stored in plain text anywhere in source code or database
DEFAULT_MOD_HASH = "1ee0a6706f91df39f270933f78334ff4d5ddc36527bf2e5400280ddb1efc9ddc"

RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "GhostWire")
RP_ORIGIN = os.getenv("RP_ORIGIN", "http://localhost:8000")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./chat.db")

SESSION_COOKIE_NAME = "chat_session"
SESSION_TTL_SECONDS = 86400 * 30  # 30 days persistent session

# --- In-Memory Ephemeral Stores ---
sessions_store: Dict[str, tuple[str, float]] = {}  # token -> (user_id_str, expire_timestamp)
webauthn_challenges: Dict[str, tuple[Any, float]] = {}  # challenge_id -> (context, expire_timestamp)


def hash_moderator_key(key: str) -> str:
    return hashlib.pbkdf2_hmac(
        'sha256',
        key.encode('utf-8'),
        MODERATOR_KEY_SALT,
        200000
    ).hex()


def verify_moderator_key(provided_key: Optional[str]) -> bool:
    if not provided_key or not isinstance(provided_key, str):
        return False
    provided_key = provided_key.strip()
    
    # 1. Check against custom hash in env if set
    env_hash = os.getenv("MODERATOR_KEY_HASH")
    if env_hash:
        return secrets.compare_digest(hash_moderator_key(provided_key), env_hash.strip())
    
    # 2. Check against raw env override if set
    env_key = os.getenv("MODERATOR_KEY", os.getenv("ADMIN_KEY"))
    if env_key:
        if secrets.compare_digest(provided_key, env_key.strip()):
            return True
        if secrets.compare_digest(hash_moderator_key(provided_key), env_key.strip()):
            return True
            
    # 3. Check against secure default cryptographic hash
    return secrets.compare_digest(hash_moderator_key(provided_key), DEFAULT_MOD_HASH)


# --- Password Hashing Helpers ---
def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        SECRET_KEY.encode('utf-8'),
        100000
    ).hex()


def verify_password(password: str, hashed: str) -> bool:
    return secrets.compare_digest(hash_password(password), hashed)


# --- Database Models (SQLModel) ---
class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    username: str = Field(index=True, unique=True, nullable=False)
    display_name: str = Field(nullable=False)
    password_hash: str = Field(nullable=False)
    webauthn_user_handle: bytes = Field(default_factory=lambda: secrets.token_bytes(64))
    is_moderator: bool = Field(default=False)
    is_banned: bool = Field(default=False)
    ban_reason: Optional[str] = Field(default=None)
    last_seen_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(UTC), sa_type=DateTime(timezone=True))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), sa_type=DateTime(timezone=True))

    @property
    def is_admin(self) -> bool:
        return self.is_moderator


class Credential(SQLModel, table=True):
    id: str = Field(primary_key=True)
    user_id: UUID = Field(foreign_key="user.id", index=True)
    public_key: bytes = Field(nullable=False)
    sign_count: int = Field(default=0)


class PrekeyBundle(SQLModel, table=True):
    user_id: UUID = Field(foreign_key="user.id", primary_key=True)
    identity_key: str = Field(nullable=False)
    signed_prekey: str = Field(nullable=False)
    signature: str = Field(nullable=False)
    one_time_prekeys_json: str = Field(default="[]", sa_type=Text)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC), sa_type=DateTime(timezone=True))


class Room(SQLModel, table=True):
    id: str = Field(primary_key=True)
    user1_id: UUID = Field(foreign_key="user.id", index=True)
    user2_id: UUID = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), sa_type=DateTime(timezone=True))


class StoredMessage(SQLModel, table=True):
    id: str = Field(primary_key=True)
    room_id: str = Field(index=True)
    sender_id: str = Field(index=True)
    recipient_id: str = Field(index=True)
    encrypted_content: str = Field(sa_type=Text)
    message_type: str = Field(default="text")  # text, image, file, audio
    reactions_json: str = Field(default="{}", sa_type=Text)
    is_read: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), sa_type=DateTime(timezone=True))


class AuditLog(SQLModel, table=True):
    id: str = Field(default_factory=lambda: f"log_{uuid4().hex[:12]}", primary_key=True)
    moderator_id: str = Field(default="mod_master", index=True)
    moderator_username: str = Field(default="Moderator", nullable=False)
    admin_id: Optional[str] = Field(default="mod_master", nullable=True)
    admin_username: Optional[str] = Field(default="Moderator", nullable=True)
    action: str = Field(nullable=False)  # "delete_user", "ban_user", "unban_user", "kick_user", "broadcast", "purge_room", "toggle_moderator", "purge_messages"
    target_id: Optional[str] = Field(default=None, index=True)
    target_username: Optional[str] = Field(default=None)
    details: Optional[str] = Field(default=None, sa_type=Text)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC), sa_type=DateTime(timezone=True))


# --- Database Engine Setup ---
engine = create_async_engine(DATABASE_URL, echo=False)
async_session_maker = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        
        def migrate_schema(sync_conn):
            inspector = inspect(sync_conn)
            tables = inspector.get_table_names()
            
            if 'user' in tables:
                user_cols = [c['name'] for c in inspector.get_columns('user')]
                if 'is_moderator' not in user_cols:
                    sync_conn.execute(text("ALTER TABLE user ADD COLUMN is_moderator BOOLEAN DEFAULT 0"))
                    if 'is_admin' in user_cols:
                        sync_conn.execute(text("UPDATE user SET is_moderator = is_admin WHERE is_admin IS NOT NULL"))
                if 'is_admin' not in user_cols:
                    sync_conn.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
                if 'is_banned' not in user_cols:
                    sync_conn.execute(text("ALTER TABLE user ADD COLUMN is_banned BOOLEAN DEFAULT 0"))
                if 'ban_reason' not in user_cols:
                    sync_conn.execute(text("ALTER TABLE user ADD COLUMN ban_reason TEXT DEFAULT NULL"))
                if 'last_seen_at' not in user_cols:
                    sync_conn.execute(text("ALTER TABLE user ADD COLUMN last_seen_at DATETIME DEFAULT NULL"))
            
            if 'storedmessage' in tables:
                columns = [c['name'] for c in inspector.get_columns('storedmessage')]
                if 'message_type' not in columns:
                    sync_conn.execute(text("ALTER TABLE storedmessage ADD COLUMN message_type TEXT DEFAULT 'text'"))
                if 'reactions_json' not in columns:
                    sync_conn.execute(text("ALTER TABLE storedmessage ADD COLUMN reactions_json TEXT DEFAULT '{}'"))
                if 'is_read' not in columns:
                    sync_conn.execute(text("ALTER TABLE storedmessage ADD COLUMN is_read BOOLEAN DEFAULT 0"))

            if 'auditlog' in tables:
                columns = [c['name'] for c in inspector.get_columns('auditlog')]
                if 'moderator_id' not in columns:
                    sync_conn.execute(text("ALTER TABLE auditlog ADD COLUMN moderator_id TEXT DEFAULT 'mod_master'"))
                    if 'admin_id' in columns:
                        sync_conn.execute(text("UPDATE auditlog SET moderator_id = admin_id WHERE admin_id IS NOT NULL"))
                if 'moderator_username' not in columns:
                    sync_conn.execute(text("ALTER TABLE auditlog ADD COLUMN moderator_username TEXT DEFAULT 'Moderator'"))
                    if 'admin_username' in columns:
                        sync_conn.execute(text("UPDATE auditlog SET moderator_username = admin_username WHERE admin_username IS NOT NULL"))
                if 'admin_id' not in columns:
                    sync_conn.execute(text("ALTER TABLE auditlog ADD COLUMN admin_id TEXT DEFAULT 'mod_master'"))
                if 'admin_username' not in columns:
                    sync_conn.execute(text("ALTER TABLE auditlog ADD COLUMN admin_username TEXT DEFAULT 'Moderator'"))
        
        await conn.run_sync(migrate_schema)


async def get_session():
    async with async_session_maker() as session:
        yield session


# --- Helper: Generate Default Prekey Bundle ---
def generate_ec_jwk_pair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    numbers = pub.public_numbers()
    x_bytes = numbers.x.to_bytes(32, byteorder='big')
    y_bytes = numbers.y.to_bytes(32, byteorder='big')
    
    pub_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": bytes_to_base64url(x_bytes),
        "y": bytes_to_base64url(y_bytes),
        "ext": True
    }
    return json.dumps(pub_jwk)


async def ensure_prekey_bundle(user_id: UUID, session: AsyncSession) -> PrekeyBundle:
    res = await session.execute(select(PrekeyBundle).where(PrekeyBundle.user_id == user_id))
    bundle = res.scalar_one_or_none()
    if not bundle:
        pub_jwk_str = generate_ec_jwk_pair()
        bundle = PrekeyBundle(
            user_id=user_id,
            identity_key=pub_jwk_str,
            signed_prekey=pub_jwk_str,
            signature="sig_default",
            one_time_prekeys_json=json.dumps([pub_jwk_str])
        )
        session.add(bundle)
        await session.commit()
        await session.refresh(bundle)
    return bundle


# --- WebSocket Connection Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.start_time: float = time.time()

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
        logger.info(f"WebSocket connected for user {user_id}")
        now_iso = datetime.now(UTC).isoformat()
        await self.broadcast_presence(user_id, True, now_iso)

    async def disconnect(self, user_id: str, websocket: WebSocket):
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                now_iso = datetime.now(UTC).isoformat()
                await self.broadcast_presence(user_id, False, now_iso)
                try:
                    async with async_session_maker() as db_session:
                        user_uuid = UUID(user_id)
                        res = await db_session.execute(select(User).where(User.id == user_uuid))
                        u = res.scalar_one_or_none()
                        if u:
                            u.last_seen_at = datetime.now(UTC)
                            db_session.add(u)
                            await db_session.commit()
                except Exception:
                    pass
        logger.info(f"WebSocket disconnected for user {user_id}")

    async def send_to_user(self, user_id: str, message: dict):
        if user_id in self.active_connections:
            for ws in list(self.active_connections[user_id]):
                try:
                    await ws.send_json(message)
                except Exception:
                    pass

    async def broadcast_presence(self, user_id: str, is_online: bool, last_seen_at: Optional[str] = None):
        if not last_seen_at:
            last_seen_at = datetime.now(UTC).isoformat()
        payload = {
            "type": "presence_update",
            "user_id": user_id,
            "is_online": is_online,
            "last_seen_at": last_seen_at
        }
        for uid, ws_list in list(self.active_connections.items()):
            for ws in list(ws_list):
                try:
                    await ws.send_json(payload)
                except Exception:
                    pass

    async def broadcast_announcement(self, title: str, message: str, severity: str = "info") -> dict:
        payload = {
            "type": "system_announcement",
            "id": f"ann_{uuid4().hex[:8]}",
            "title": title,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now(UTC).isoformat()
        }
        for uid, ws_list in list(self.active_connections.items()):
            for ws in list(ws_list):
                try:
                    await ws.send_json(payload)
                except Exception:
                    pass
        return payload

    async def broadcast_user_deleted(self, user_id: str):
        payload = {"type": "user_deleted", "user_id": user_id}
        for uid, ws_list in list(self.active_connections.items()):
            for ws in list(ws_list):
                try:
                    await ws.send_json(payload)
                except Exception:
                    pass

    async def disconnect_user(self, user_id: str, reason: str = "Session terminated by moderator"):
        if user_id in self.active_connections:
            sockets = list(self.active_connections[user_id])
            for ws in sockets:
                try:
                    await ws.send_json({"type": "force_logout", "reason": reason})
                    await ws.close(code=4003)
                except Exception:
                    pass
            self.active_connections.pop(user_id, None)
            await self.broadcast_presence(user_id, False)

    def is_user_online(self, user_id: str) -> bool:
        return user_id in self.active_connections and len(self.active_connections[user_id]) > 0

    def get_online_user_ids(self) -> List[str]:
        return list(self.active_connections.keys())

    def get_total_connections_count(self) -> int:
        return sum(len(ws_list) for ws_list in self.active_connections.values())


ws_manager = ConnectionManager()


# --- Auth Helper Dependencies ---
async def get_current_user(
    chat_session: Optional[str] = Cookie(None),
    token: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
    session: AsyncSession = Depends(get_session)
) -> User:
    auth_token = None
    if authorization and authorization.startswith("Bearer "):
        auth_token = authorization.split(" ")[1]
    if not auth_token:
        auth_token = token or chat_session

    if not auth_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    
    session_data = sessions_store.get(auth_token)
    if not session_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")
    
    user_id_str, expire_at = session_data
    if time.time() > expire_at:
        sessions_store.pop(auth_token, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    
    try:
        user_uuid = UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed session")
    
    res = await session.execute(select(User).where(User.id == user_uuid))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    
    if user.is_banned:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is suspended. Reason: {user.ban_reason or 'Platform violation'}"
        )
    
    user.last_seen_at = datetime.now(UTC)
    session.add(user)
    await session.commit()
    return user


class ModeratorContext:
    def __init__(self, id: str, username: str, is_master_key: bool = False, user: Optional[User] = None):
        self.id = id
        self.username = username
        self.is_master_key = is_master_key
        self.user = user


async def get_current_moderator(
    x_moderator_key: Optional[str] = Header(None),
    moderator_key: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
    chat_session: Optional[str] = Cookie(None),
    token: Optional[str] = Query(None),
    session: AsyncSession = Depends(get_session)
) -> ModeratorContext:
    # 1. Check direct moderator key
    given_key = x_moderator_key or moderator_key
    if not given_key and authorization and authorization.startswith("Bearer "):
        bearer_val = authorization.split(" ")[1]
        if verify_moderator_key(bearer_val):
            given_key = bearer_val

    if given_key and verify_moderator_key(given_key):
        return ModeratorContext(id="mod_master", username="Moderator", is_master_key=True)

    # 2. Check token from sessions_store
    auth_token = None
    if authorization and authorization.startswith("Bearer "):
        auth_token = authorization.split(" ")[1]
    if not auth_token:
        auth_token = token or chat_session

    if auth_token and auth_token in sessions_store:
        user_id_str, expire_at = sessions_store[auth_token]
        if time.time() <= expire_at:
            if user_id_str == "mod_master":
                return ModeratorContext(id="mod_master", username="Moderator", is_master_key=True)
            try:
                user_uuid = UUID(user_id_str)
                res = await session.execute(select(User).where(User.id == user_uuid))
                user = res.scalar_one_or_none()
                if user and user.is_moderator and not user.is_banned:
                    return ModeratorContext(id=str(user.id), username=user.username, is_master_key=False, user=user)
            except ValueError:
                pass

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Moderator privileges required. Provide a valid Moderator Access Key."
    )


# --- Pydantic Schemas ---
class SimpleLoginRequest(BaseModel):
    username: str
    password: str
    display_name: Optional[str] = None
    moderator_key: Optional[str] = None
    admin_key: Optional[str] = None


class ModeratorLoginRequest(BaseModel):
    key: Optional[str] = None
    moderator_key: Optional[str] = None


class BanUserRequest(BaseModel):
    reason: Optional[str] = "Violation of platform community guidelines"


class BroadcastRequest(BaseModel):
    title: Optional[str] = "System Announcement"
    message: str
    severity: Optional[str] = "info"  # info, warning, alert, success


class UploadKeysRequest(BaseModel):
    identity_key: str
    signed_prekey: str
    signature: str
    one_time_prekeys: List[str]


class CreateRoomRequest(BaseModel):
    participant_id: str


class SendMessageRequest(BaseModel):
    room_id: str
    recipient_id: str
    encrypted_content: str
    message_type: Optional[str] = "text"


# --- FastAPI App Definition ---
app = FastAPI(
    title="GhostWire - Encrypted Messaging & Moderator Operations Suite",
    version="2.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

os.makedirs(os.path.join(os.path.dirname(__file__), "static"), exist_ok=True)
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


@app.on_event("startup")
async def on_startup():
    await init_db()
    logger.info("Database initialized with moderator operations suite.")


# Serve main single-page UI
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>GhostWire</h1><p>index.html missing!</p>"


# Serve moderator console portal
@app.get("/moderator", response_class=HTMLResponse)
async def serve_moderator():
    mod_path = os.path.join(os.path.dirname(__file__), "moderator.html")
    if os.path.exists(mod_path):
        with open(mod_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>GhostWire - Moderator Console</h1><p>moderator.html missing!</p>"


# --- Auth Routes ---
@app.post("/api/auth/simple-login")
async def simple_login(
    body: SimpleLoginRequest,
    response: Response,
    session: AsyncSession = Depends(get_session)
):
    username = body.username.strip().lower()
    password = body.password.strip()

    if not username or len(username) < 2:
        raise HTTPException(status_code=400, detail="Username must be at least 2 characters")

    if not password or len(password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")

    # Check existing users count to grant moderator to first user or if key matches
    user_count_res = await session.execute(select(User))
    all_users = user_count_res.scalars().all()
    is_first_user = len(all_users) == 0
    key_supplied = body.moderator_key or body.admin_key
    is_mod_requested = bool(key_supplied and verify_moderator_key(key_supplied))

    res = await session.execute(select(User).where(User.username == username))
    user = res.scalar_one_or_none()

    if not user:
        user = User(
            username=username,
            display_name=body.display_name or username.capitalize(),
            password_hash=hash_password(password),
            is_moderator=False,
            last_seen_at=datetime.now(UTC)
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
    else:
        if not verify_password(password, user.password_hash):
            raise HTTPException(status_code=401, detail="Incorrect password. Access denied.")
        if user.is_banned:
            raise HTTPException(
                status_code=403,
                detail=f"Your account has been suspended by a moderator. Reason: {user.ban_reason or 'Platform violation'}"
            )
        user.last_seen_at = datetime.now(UTC)
        session.add(user)
        await session.commit()

    await ensure_prekey_bundle(user.id, session)

    token = secrets.token_urlsafe(32)
    sessions_store[token] = (str(user.id), time.time() + SESSION_TTL_SECONDS)
    response.set_cookie(key=SESSION_COOKIE_NAME, value=token, httponly=False, samesite="lax")

    return {
        "status": "ok",
        "token": token,
        "user": {
            "id": str(user.id),
            "username": user.username,
            "display_name": user.display_name,
            "is_moderator": user.is_moderator,
            "is_admin": user.is_moderator,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_seen_at": user.last_seen_at.isoformat() if user.last_seen_at else None,
        }
    }


@app.get("/api/auth/me")
async def get_me(user: User = Depends(get_current_user)):
    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "is_moderator": user.is_moderator,
        "is_admin": user.is_moderator,
        "is_banned": user.is_banned,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_seen_at": user.last_seen_at.isoformat() if user.last_seen_at else None,
    }


@app.post("/api/auth/logout")
async def logout(
    response: Response,
    chat_session: Optional[str] = Cookie(None)
):
    if chat_session:
        sessions_store.pop(chat_session, None)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"status": "logged_out"}


# --- User Directory & Contacts ---
@app.get("/api/users")
@app.get("/api/users/search")
async def get_users_directory(
    q: Optional[str] = Query(None),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    # Hide banned users from directory for regular users
    stmt = select(User).where((User.id != user.id) & (User.is_banned == False))
    if q and q.strip():
        query_str = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(User.username.like(query_str), User.display_name.like(query_str)))
    
    stmt = stmt.limit(100)
    res = await session.execute(stmt)
    users = res.scalars().all()

    output = []
    for u in users:
        res_room = await session.execute(
            select(Room).where(
                ((Room.user1_id == user.id) & (Room.user2_id == u.id)) |
                ((Room.user1_id == u.id) & (Room.user2_id == user.id))
            )
        )
        room = res_room.scalar_one_or_none()
        room_id = room.id if room else None

        last_msg = None
        if room_id:
            res_msg = await session.execute(
                select(StoredMessage).where(StoredMessage.room_id == room_id).order_by(StoredMessage.created_at.desc()).limit(1)
            )
            latest = res_msg.scalar_one_or_none()
            if latest:
                last_msg = {
                    "id": latest.id,
                    "sender_id": latest.sender_id,
                    "encrypted_content": latest.encrypted_content,
                    "message_type": latest.message_type,
                    "created_at": latest.created_at.isoformat()
                }

        output.append({
            "id": str(u.id),
            "username": u.username,
            "display_name": u.display_name,
            "is_online": ws_manager.is_user_online(str(u.id)),
            "is_moderator": u.is_moderator,
            "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "room_id": room_id,
            "last_message": last_msg
        })

    return output


@app.post("/api/encryption/upload-keys")
async def upload_keys(
    body: UploadKeysRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    res = await session.execute(select(PrekeyBundle).where(PrekeyBundle.user_id == user.id))
    bundle = res.scalar_one_or_none()

    if not bundle:
        bundle = PrekeyBundle(
            user_id=user.id,
            identity_key=body.identity_key,
            signed_prekey=body.signed_prekey,
            signature=body.signature,
            one_time_prekeys_json=json.dumps(body.one_time_prekeys)
        )
        session.add(bundle)
    else:
        bundle.identity_key = body.identity_key
        bundle.signed_prekey = body.signed_prekey
        bundle.signature = body.signature
        bundle.one_time_prekeys_json = json.dumps(body.one_time_prekeys)
        bundle.updated_at = datetime.now(UTC)

    await session.commit()
    logger.info(f"Public prekey bundle uploaded for user {user.id}")
    return {"status": "keys_stored"}


@app.get("/api/encryption/bundle/{user_id_str}")
async def get_bundle(
    user_id_str: str,
    session: AsyncSession = Depends(get_session)
):
    try:
        user_uuid = UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user UUID")

    bundle = await ensure_prekey_bundle(user_uuid, session)
    ot_keys = json.loads(bundle.one_time_prekeys_json)
    chosen_opk = ot_keys[0] if ot_keys else bundle.identity_key

    return {
        "user_id": str(bundle.user_id),
        "identity_key": bundle.identity_key,
        "signed_prekey": bundle.signed_prekey,
        "signature": bundle.signature,
        "one_time_prekey": chosen_opk
    }


# --- Rooms & Messages ---
@app.post("/api/rooms")
async def create_room(
    body: CreateRoomRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    try:
        target_uuid = UUID(body.participant_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid participant_id")

    if target_uuid == user.id:
        raise HTTPException(status_code=400, detail="Cannot start room with yourself")

    res = await session.execute(select(User).where(User.id == target_uuid))
    target = res.scalar_one_or_none()
    if not target or target.is_banned:
        raise HTTPException(status_code=404, detail="Participant not found or unavailable")

    res = await session.execute(
        select(Room).where(
            ((Room.user1_id == user.id) & (Room.user2_id == target.id)) |
            ((Room.user1_id == target.id) & (Room.user2_id == user.id))
        )
    )
    existing = res.scalar_one_or_none()

    if existing:
        return {
            "id": existing.id,
            "name": target.display_name,
            "participant": {"id": str(target.id), "username": target.username, "display_name": target.display_name}
        }

    room_id = f"room_{uuid4().hex[:12]}"
    new_room = Room(id=room_id, user1_id=user.id, user2_id=target.id)
    session.add(new_room)
    await session.commit()

    await ws_manager.send_to_user(
        str(target.id),
        {
            "type": "room_created",
            "room": {
                "id": room_id,
                "name": user.display_name,
                "participant": {"id": str(user.id), "username": user.username, "display_name": user.display_name}
            }
        }
    )

    return {
        "id": room_id,
        "name": target.display_name,
        "participant": {"id": str(target.id), "username": target.username, "display_name": target.display_name}
    }


@app.get("/api/rooms/{room_id}/messages")
async def get_messages(
    room_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    res = await session.execute(
        select(StoredMessage).where(StoredMessage.room_id == room_id).order_by(StoredMessage.created_at.asc())
    )
    msgs = res.scalars().all()
    
    # Mark unread messages as read
    for m in msgs:
        if m.recipient_id == str(user.id) and not m.is_read:
            m.is_read = True
    await session.commit()

    return [
        {
            "id": m.id,
            "room_id": m.room_id,
            "sender_id": m.sender_id,
            "recipient_id": m.recipient_id,
            "encrypted_content": m.encrypted_content,
            "message_type": m.message_type,
            "reactions": json.loads(m.reactions_json or "{}"),
            "is_read": m.is_read,
            "created_at": m.created_at.isoformat()
        }
        for m in msgs
    ]


@app.post("/api/messages")
async def send_message_rest(
    body: SendMessageRequest,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session)
):
    msg_id = f"msg_{uuid4().hex}"
    now_iso = datetime.now(UTC).isoformat()

    db_msg = StoredMessage(
        id=msg_id,
        room_id=body.room_id,
        sender_id=str(user.id),
        recipient_id=body.recipient_id,
        encrypted_content=body.encrypted_content,
        message_type=body.message_type or "text"
    )
    session.add(db_msg)
    await session.commit()

    payload = {
        "type": "encrypted_message",
        "id": msg_id,
        "room_id": body.room_id,
        "sender_id": str(user.id),
        "recipient_id": body.recipient_id,
        "encrypted_content": body.encrypted_content,
        "message_type": body.message_type or "text",
        "reactions": {},
        "is_read": False,
        "created_at": now_iso
    }

    await ws_manager.send_to_user(body.recipient_id, payload)
    await ws_manager.send_to_user(str(user.id), payload)

    return payload


# =====================================================================
# --- MODERATOR OPERATIONS & MANAGEMENT SUITE ---
# =====================================================================

@app.post("/api/moderator/login")
async def moderator_login(
    body: ModeratorLoginRequest,
    response: Response
):
    """
    Moderator Login: Authenticate using encrypted Master Moderator Key
    """
    key = (body.key or body.moderator_key or "").strip()
    if not key or not verify_moderator_key(key):
        raise HTTPException(status_code=401, detail="Invalid Moderator Access Key. Access denied.")

    token = f"mod_{secrets.token_urlsafe(32)}"
    sessions_store[token] = ("mod_master", time.time() + SESSION_TTL_SECONDS)
    response.set_cookie(key=SESSION_COOKIE_NAME, value=token, httponly=False, samesite="lax")
    return {
        "status": "ok",
        "token": token,
        "role": "moderator",
        "username": "Moderator",
        "is_master": True
    }


@app.get("/api/moderator/overview")
async def get_moderator_overview(
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Live platform metrics: user counts, online/offline breakdown, messages, rooms, and metrics.
    """
    res_users = await session.execute(select(User))
    all_users = res_users.scalars().all()
    total_users = len(all_users)

    online_ids = set(ws_manager.get_online_user_ids())
    online_count = sum(1 for u in all_users if str(u.id) in online_ids)
    offline_count = total_users - online_count
    banned_count = sum(1 for u in all_users if u.is_banned)
    moderator_count = 1  # Exactly one Master Moderator in system

    res_rooms = await session.execute(select(Room))
    all_rooms = res_rooms.scalars().all()
    total_rooms = len(all_rooms)

    res_msgs = await session.execute(select(StoredMessage))
    all_msgs = res_msgs.scalars().all()
    total_msgs = len(all_msgs)

    # Message type breakdown
    msg_types = {"text": 0, "image": 0, "file": 0, "audio": 0}
    for m in all_msgs:
        t = m.message_type or "text"
        msg_types[t] = msg_types.get(t, 0) + 1

    uptime_seconds = int(time.time() - ws_manager.start_time)

    return {
        "total_users": total_users,
        "online_users": online_count,
        "offline_users": offline_count,
        "banned_users": banned_count,
        "moderator_users": moderator_count,
        "admin_users": moderator_count,
        "total_rooms": total_rooms,
        "total_messages": total_msgs,
        "message_types": msg_types,
        "active_ws_connections": ws_manager.get_total_connections_count(),
        "uptime_seconds": uptime_seconds,
        "moderator": {
            "id": moderator.id,
            "username": moderator.username,
            "is_master": moderator.is_master_key
        }
    }


@app.get("/api/moderator/users")
async def get_moderator_users(
    q: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),  # all, online, offline, banned
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Search, filter, and inspect registered users with activity and presence metrics.
    """
    stmt = select(User)
    if q and q.strip():
        search_str = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(User.username.like(search_str), User.display_name.like(search_str)))

    if status_filter == "banned":
        stmt = stmt.where(User.is_banned == True)

    stmt = stmt.order_by(User.created_at.desc())
    res = await session.execute(stmt)
    users = res.scalars().all()

    online_ids = set(ws_manager.get_online_user_ids())

    # Filter online/offline in-memory if requested
    if status_filter == "online":
        users = [u for u in users if str(u.id) in online_ids]
    elif status_filter == "offline":
        users = [u for u in users if str(u.id) not in online_ids]

    total_filtered = len(users)
    start_idx = (page - 1) * limit
    paged_users = users[start_idx : start_idx + limit]

    user_list = []
    for u in paged_users:
        uid_str = str(u.id)
        # Count messages sent
        m_res = await session.execute(select(StoredMessage).where(StoredMessage.sender_id == uid_str))
        msg_count = len(m_res.scalars().all())

        # Count active rooms
        r_res = await session.execute(
            select(Room).where((Room.user1_id == u.id) | (Room.user2_id == u.id))
        )
        rooms_count = len(r_res.scalars().all())

        user_list.append({
            "id": uid_str,
            "username": u.username,
            "display_name": u.display_name,
            "is_moderator": u.is_moderator,
            "is_admin": u.is_moderator,
            "is_banned": u.is_banned,
            "ban_reason": u.ban_reason,
            "is_online": uid_str in online_ids,
            "message_count": msg_count,
            "rooms_count": rooms_count,
            "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        })

    return {
        "total": total_filtered,
        "page": page,
        "limit": limit,
        "pages": (total_filtered + limit - 1) // limit if total_filtered > 0 else 1,
        "users": user_list
    }


@app.get("/api/moderator/users/{user_id_str}")
async def get_moderator_user_detail(
    user_id_str: str,
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Get detailed user statistics, conversation rooms, and cryptographic prekey status.
    """
    try:
        user_uuid = UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user UUID")

    res = await session.execute(select(User).where(User.id == user_uuid))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    res_rooms = await session.execute(
        select(Room).where((Room.user1_id == user_uuid) | (Room.user2_id == user_uuid))
    )
    rooms = res_rooms.scalars().all()

    room_details = []
    for r in rooms:
        other_id = r.user2_id if r.user1_id == user_uuid else r.user1_id
        res_other = await session.execute(select(User).where(User.id == other_id))
        other_user = res_other.scalar_one_or_none()
        
        m_count_res = await session.execute(select(StoredMessage).where(StoredMessage.room_id == r.id))
        m_count = len(m_count_res.scalars().all())

        room_details.append({
            "room_id": r.id,
            "partner_id": str(other_id),
            "partner_username": other_user.username if other_user else "Deleted User",
            "partner_display_name": other_user.display_name if other_user else "Deleted User",
            "message_count": m_count,
            "created_at": r.created_at.isoformat() if r.created_at else None
        })

    # Prekeys
    pk_res = await session.execute(select(PrekeyBundle).where(PrekeyBundle.user_id == user_uuid))
    pk = pk_res.scalar_one_or_none()
    has_prekeys = pk is not None

    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "is_moderator": user.is_moderator,
        "is_admin": user.is_moderator,
        "is_banned": user.is_banned,
        "ban_reason": user.ban_reason,
        "is_online": ws_manager.is_user_online(str(user.id)),
        "has_prekeys": has_prekeys,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_seen_at": user.last_seen_at.isoformat() if user.last_seen_at else None,
        "rooms": room_details
    }


@app.delete("/api/moderator/users/{user_id_str}")
async def delete_user_by_moderator(
    user_id_str: str,
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Permanently deletes a user and cascades: terminates sessions, deletes prekeys, credentials, rooms, messages.
    """
    try:
        user_uuid = UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user UUID")

    res = await session.execute(select(User).where(User.id == user_uuid))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent deleting self
    if moderator.user and moderator.user.id == user_uuid:
        raise HTTPException(status_code=400, detail="Cannot delete your own moderator account.")

    username_cached = user.username

    # 1. Force Disconnect active WebSockets
    await ws_manager.disconnect_user(user_id_str, "Your account has been deleted by a moderator.")

    # 2. Invalidate sessions in memory
    tokens_to_remove = [k for k, v in sessions_store.items() if v[0] == user_id_str]
    for token in tokens_to_remove:
        sessions_store.pop(token, None)

    # 3. Cascade delete credentials
    res_creds = await session.execute(select(Credential).where(Credential.user_id == user_uuid))
    for c in res_creds.scalars().all():
        await session.delete(c)

    # 4. Cascade delete prekey bundle
    res_pk = await session.execute(select(PrekeyBundle).where(PrekeyBundle.user_id == user_uuid))
    for pk in res_pk.scalars().all():
        await session.delete(pk)

    # 5. Cascade delete rooms & messages
    res_rooms = await session.execute(
        select(Room).where((Room.user1_id == user_uuid) | (Room.user2_id == user_uuid))
    )
    for r in res_rooms.scalars().all():
        res_m = await session.execute(select(StoredMessage).where(StoredMessage.room_id == r.id))
        for m in res_m.scalars().all():
            await session.delete(m)
        await session.delete(r)

    # 6. Delete orphan messages sent or received by user
    res_orphan = await session.execute(
        select(StoredMessage).where((StoredMessage.sender_id == user_id_str) | (StoredMessage.recipient_id == user_id_str))
    )
    for m in res_orphan.scalars().all():
        await session.delete(m)

    # 7. Delete User entity
    await session.delete(user)

    # 8. Record in Audit Log
    log_entry = AuditLog(
        moderator_id=moderator.id,
        moderator_username=moderator.username,
        action="delete_user",
        target_id=user_id_str,
        target_username=username_cached,
        details="Permanent user deletion and cascade wiping of all associated chat history."
    )
    session.add(log_entry)
    await session.commit()

    # 9. Broadcast user removal to all connected clients
    await ws_manager.broadcast_user_deleted(user_id_str)
    logger.info(f"User {username_cached} ({user_id_str}) permanently deleted by {moderator.username}")

    return {
        "status": "deleted",
        "user_id": user_id_str,
        "username": username_cached,
        "message": "User and all associated data successfully removed."
    }


@app.post("/api/moderator/users/{user_id_str}/ban")
async def ban_user_by_moderator(
    user_id_str: str,
    body: BanUserRequest,
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Bans a user from connecting or logging in, and terminates all active sessions immediately.
    """
    try:
        user_uuid = UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user UUID")

    res = await session.execute(select(User).where(User.id == user_uuid))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if moderator.user and moderator.user.id == user_uuid:
        raise HTTPException(status_code=400, detail="Cannot ban your own account.")

    reason = body.reason.strip() if body.reason else "Violation of platform community guidelines"
    user.is_banned = True
    user.ban_reason = reason
    session.add(user)

    # Invalidate sessions
    tokens_to_remove = [k for k, v in sessions_store.items() if v[0] == user_id_str]
    for token in tokens_to_remove:
        sessions_store.pop(token, None)

    # Disconnect active socket connections
    await ws_manager.disconnect_user(user_id_str, f"Your account has been suspended by a moderator: {reason}")

    # Record Audit Log
    log_entry = AuditLog(
        moderator_id=moderator.id,
        moderator_username=moderator.username,
        action="ban_user",
        target_id=user_id_str,
        target_username=user.username,
        details=f"Reason: {reason}"
    )
    session.add(log_entry)
    await session.commit()

    return {
        "status": "banned",
        "user_id": user_id_str,
        "username": user.username,
        "ban_reason": reason
    }


@app.post("/api/moderator/users/{user_id_str}/unban")
async def unban_user_by_moderator(
    user_id_str: str,
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Removes suspension and restores user access.
    """
    try:
        user_uuid = UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user UUID")

    res = await session.execute(select(User).where(User.id == user_uuid))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_banned = False
    user.ban_reason = None
    session.add(user)

    log_entry = AuditLog(
        moderator_id=moderator.id,
        moderator_username=moderator.username,
        action="unban_user",
        target_id=user_id_str,
        target_username=user.username,
        details="Suspension revoked by moderator."
    )
    session.add(log_entry)
    await session.commit()

    return {
        "status": "unbanned",
        "user_id": user_id_str,
        "username": user.username
    }


@app.post("/api/moderator/users/{user_id_str}/kick")
async def kick_user_by_moderator(
    user_id_str: str,
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Immediately forces disconnection of active WebSocket connections and invalidates current session.
    """
    try:
        user_uuid = UUID(user_id_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user UUID")

    res = await session.execute(select(User).where(User.id == user_uuid))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Invalidate sessions
    tokens_to_remove = [k for k, v in sessions_store.items() if v[0] == user_id_str]
    for token in tokens_to_remove:
        sessions_store.pop(token, None)

    await ws_manager.disconnect_user(user_id_str, "You have been disconnected by a moderator.")

    log_entry = AuditLog(
        moderator_id=moderator.id,
        moderator_username=moderator.username,
        action="kick_user",
        target_id=user_id_str,
        target_username=user.username,
        details="Active session terminated and socket disconnected."
    )
    session.add(log_entry)
    await session.commit()

    return {
        "status": "kicked",
        "user_id": user_id_str,
        "username": user.username
    }


@app.post("/api/moderator/users/{user_id_str}/toggle-moderator")
@app.post("/api/admin/users/{user_id_str}/toggle-admin")
async def toggle_moderator_by_moderator(
    user_id_str: str,
    moderator: ModeratorContext = Depends(get_current_moderator)
):
    """
    Disabled: There is strictly only one Master Moderator in the platform.
    """
    raise HTTPException(
        status_code=400,
        detail="User promotion is disabled. The system operates with a single Master Moderator accessed via the Moderator Access Key."
    )


@app.post("/api/moderator/broadcast")
async def broadcast_announcement_by_moderator(
    body: BroadcastRequest,
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Broadcasts a real-time system announcement to all currently connected users.
    """
    if not body.message or not body.message.strip():
        raise HTTPException(status_code=400, detail="Broadcast message cannot be empty.")

    title = body.title.strip() if body.title else "System Announcement"
    msg = body.message.strip()
    sev = body.severity if body.severity in ["info", "warning", "alert", "success"] else "info"

    payload = await ws_manager.broadcast_announcement(title, msg, sev)

    log_entry = AuditLog(
        moderator_id=moderator.id,
        moderator_username=moderator.username,
        action="broadcast",
        details=f"[{sev.upper()}] {title}: {msg}"
    )
    session.add(log_entry)
    await session.commit()

    return {
        "status": "broadcasted",
        "recipients_count": ws_manager.get_total_connections_count(),
        "payload": payload
    }


@app.get("/api/moderator/rooms")
async def get_moderator_rooms(
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Lists all conversation rooms, participant details, and message volume.
    """
    res_rooms = await session.execute(select(Room).order_by(Room.created_at.desc()))
    rooms = res_rooms.scalars().all()

    output = []
    for r in rooms:
        res_u1 = await session.execute(select(User).where(User.id == r.user1_id))
        u1 = res_u1.scalar_one_or_none()

        res_u2 = await session.execute(select(User).where(User.id == r.user2_id))
        u2 = res_u2.scalar_one_or_none()

        res_msgs = await session.execute(
            select(StoredMessage).where(StoredMessage.room_id == r.id).order_by(StoredMessage.created_at.desc())
        )
        msgs = res_msgs.scalars().all()
        last_msg = msgs[0] if msgs else None

        output.append({
            "id": r.id,
            "user1": {"id": str(r.user1_id), "username": u1.username if u1 else "Deleted", "display_name": u1.display_name if u1 else "Deleted"},
            "user2": {"id": str(r.user2_id), "username": u2.username if u2 else "Deleted", "display_name": u2.display_name if u2 else "Deleted"},
            "message_count": len(msgs),
            "last_message_at": last_msg.created_at.isoformat() if last_msg and last_msg.created_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None
        })

    return output


@app.delete("/api/moderator/rooms/{room_id}")
async def purge_room_by_moderator(
    room_id: str,
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Purges a room and all stored encrypted messages within it.
    """
    res_room = await session.execute(select(Room).where(Room.id == room_id))
    room = res_room.scalar_one_or_none()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    res_msgs = await session.execute(select(StoredMessage).where(StoredMessage.room_id == room_id))
    for m in res_msgs.scalars().all():
        await session.delete(m)

    await session.delete(room)

    log_entry = AuditLog(
        moderator_id=moderator.id,
        moderator_username=moderator.username,
        action="purge_room",
        target_id=room_id,
        details="Purged conversation room and all its messages."
    )
    session.add(log_entry)
    await session.commit()

    return {"status": "room_purged", "room_id": room_id}


@app.delete("/api/moderator/messages/purge-all")
async def purge_all_messages_by_moderator(
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Purges all stored messages across the platform.
    """
    res_msgs = await session.execute(select(StoredMessage))
    all_msgs = res_msgs.scalars().all()
    count = len(all_msgs)
    for m in all_msgs:
        await session.delete(m)

    log_entry = AuditLog(
        moderator_id=moderator.id,
        moderator_username=moderator.username,
        action="purge_messages",
        details=f"Purged {count} stored messages platform-wide."
    )
    session.add(log_entry)
    await session.commit()

    return {"status": "messages_purged", "count": count}


@app.get("/api/moderator/audit-logs")
async def get_moderator_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Retrieves recent moderation activity logs.
    """
    res = await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit))
    logs = res.scalars().all()
    return [
        {
            "id": l.id,
            "moderator_id": l.moderator_id,
            "moderator_username": l.moderator_username,
            "admin_username": l.moderator_username,
            "action": l.action,
            "target_id": l.target_id,
            "target_username": l.target_username,
            "details": l.details,
            "created_at": l.created_at.isoformat() if l.created_at else None
        }
        for l in logs
    ]


@app.get("/api/moderator/export")
async def export_moderator_data(
    moderator: ModeratorContext = Depends(get_current_moderator),
    session: AsyncSession = Depends(get_session)
):
    """
    Exports a comprehensive JSON report of system status and registered users.
    """
    res_users = await session.execute(select(User))
    users = res_users.scalars().all()

    res_rooms = await session.execute(select(Room))
    rooms = res_rooms.scalars().all()

    res_msgs = await session.execute(select(StoredMessage))
    msgs = res_msgs.scalars().all()

    online_ids = set(ws_manager.get_online_user_ids())

    return {
        "export_timestamp": datetime.now(UTC).isoformat(),
        "exported_by": moderator.username,
        "summary": {
            "total_users": len(users),
            "online_users": len(online_ids),
            "total_rooms": len(rooms),
            "total_messages": len(msgs)
        },
        "users": [
            {
                "id": str(u.id),
                "username": u.username,
                "display_name": u.display_name,
                "is_moderator": u.is_moderator,
                "is_banned": u.is_banned,
                "is_online": str(u.id) in online_ids,
                "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None,
                "created_at": u.created_at.isoformat() if u.created_at else None
            }
            for u in users
        ]
    }


# =====================================================================
# --- WEBSOCKET REAL-TIME HANDLER ---
# =====================================================================

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    chat_session: Optional[str] = Cookie(None)
):
    auth_token = token or chat_session
    if not auth_token or auth_token not in sessions_store:
        await websocket.close(code=4001)
        return

    user_id_str, expire_at = sessions_store[auth_token]
    if time.time() > expire_at:
        await websocket.close(code=4001)
        return

    # Check if user is banned or deleted
    if user_id_str != "mod_master":
        async with async_session_maker() as db_session:
            try:
                user_uuid = UUID(user_id_str)
                res = await db_session.execute(select(User).where(User.id == user_uuid))
                u = res.scalar_one_or_none()
                if not u or u.is_banned:
                    await websocket.close(code=4003)
                    return
                u.last_seen_at = datetime.now(UTC)
                await db_session.commit()
            except Exception:
                pass

    await ws_manager.connect(user_id_str, websocket)

    try:
        while True:
            data_str = await websocket.receive_text()
            try:
                msg_data = json.loads(data_str)
            except Exception:
                continue

            msg_type = msg_data.get("type")

            if msg_type == "encrypted_message":
                room_id = msg_data.get("room_id")
                recipient_id = msg_data.get("recipient_id")
                encrypted_content = msg_data.get("encrypted_content")
                m_type = msg_data.get("message_type", "text")

                if room_id and recipient_id and encrypted_content:
                    msg_id = f"msg_{uuid4().hex}"
                    now_iso = datetime.now(UTC).isoformat()

                    async with async_session_maker() as db_session:
                        db_msg = StoredMessage(
                            id=msg_id,
                            room_id=room_id,
                            sender_id=user_id_str,
                            recipient_id=recipient_id,
                            encrypted_content=encrypted_content,
                            message_type=m_type
                        )
                        db_session.add(db_msg)
                        await db_session.commit()

                    payload = {
                        "type": "encrypted_message",
                        "id": msg_id,
                        "room_id": room_id,
                        "sender_id": user_id_str,
                        "recipient_id": recipient_id,
                        "encrypted_content": encrypted_content,
                        "message_type": m_type,
                        "reactions": {},
                        "is_read": False,
                        "created_at": now_iso
                    }

                    await ws_manager.send_to_user(recipient_id, payload)
                    await ws_manager.send_to_user(user_id_str, payload)

            elif msg_type == "reaction":
                msg_id = msg_data.get("message_id")
                emoji = msg_data.get("emoji")
                if msg_id and emoji:
                    async with async_session_maker() as db_session:
                        res = await db_session.execute(select(StoredMessage).where(StoredMessage.id == msg_id))
                        msg = res.scalar_one_or_none()
                        if msg:
                            reactions = json.loads(msg.reactions_json or "{}")
                            if emoji not in reactions:
                                reactions[emoji] = []
                            if user_id_str not in reactions[emoji]:
                                reactions[emoji].append(user_id_str)
                            else:
                                reactions[emoji].remove(user_id_str)
                            msg.reactions_json = json.dumps(reactions)
                            await db_session.commit()

                            payload = {
                                "type": "reaction_update",
                                "message_id": msg_id,
                                "room_id": msg.room_id,
                                "reactions": reactions
                            }
                            await ws_manager.send_to_user(msg.sender_id, payload)
                            await ws_manager.send_to_user(msg.recipient_id, payload)

            elif msg_type == "read_ack":
                room_id = msg_data.get("room_id")
                if room_id:
                    async with async_session_maker() as db_session:
                        res = await db_session.execute(
                            select(StoredMessage).where(
                                (StoredMessage.room_id == room_id) &
                                (StoredMessage.recipient_id == user_id_str) &
                                (StoredMessage.is_read == False)
                            )
                        )
                        unread_msgs = res.scalars().all()
                        for m in unread_msgs:
                            m.is_read = True
                        await db_session.commit()

                        if unread_msgs:
                            sender_id = unread_msgs[0].sender_id
                            await ws_manager.send_to_user(
                                sender_id,
                                {"type": "read_receipt", "room_id": room_id, "reader_id": user_id_str}
                            )

            elif msg_type == "typing":
                recipient_id = msg_data.get("recipient_id")
                if recipient_id:
                    await ws_manager.send_to_user(
                        recipient_id,
                        {
                            "type": "typing",
                            "room_id": msg_data.get("room_id"),
                            "sender_id": user_id_str,
                            "is_typing": msg_data.get("is_typing", True)
                        }
                    )

            elif msg_type in (
                "webrtc_call_request",
                "webrtc_call_accept",
                "webrtc_call_reject",
                "webrtc_call_end",
                "webrtc_offer",
                "webrtc_answer",
                "webrtc_ice_candidate"
            ):
                recipient_id = msg_data.get("recipient_id")
                if recipient_id:
                    msg_data["sender_id"] = user_id_str
                    await ws_manager.send_to_user(recipient_id, msg_data)

    except WebSocketDisconnect:
        await ws_manager.disconnect(user_id_str, websocket)
