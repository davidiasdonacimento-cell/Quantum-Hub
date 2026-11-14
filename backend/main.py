import os, secrets, hashlib, hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, String, Text, DateTime, Boolean, ForeignKey, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

SECRET = os.getenv("JWT_SECRET", "local-development-secret-change-me")
ALGORITHM = "HS256"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./quantum_hub.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="member")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(140))
    description: Mapped[str] = mapped_column(Text, default="")
    color: Mapped[str] = mapped_column(String(20), default="#36bffa")
    status: Mapped[str] = mapped_column(String(30), default="active")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Task(Base):
    __tablename__ = "tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="todo")
    priority: Mapped[str] = mapped_column(String(20), default="normal")
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    project_id: Mapped[Optional[int]] = mapped_column(ForeignKey("projects.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(180))
    content: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(180))
    message: Mapped[str] = mapped_column(Text, default="")
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
class LoginIn(BaseModel):
    email: EmailStr
    password: str
class ProjectIn(BaseModel):
    name: str = Field(min_length=2, max_length=140)
    description: str = ""
    color: str = "#36bffa"
    status: str = "active"
class TaskIn(BaseModel):
    title: str = Field(min_length=2, max_length=180)
    description: str = ""
    status: str = "todo"
    priority: str = "normal"
    project_id: Optional[int] = None
    due_date: Optional[datetime] = None
class NoteIn(BaseModel):
    title: str = Field(min_length=1, max_length=180)
    content: str = ""
class ProfileIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)

def db_dep():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + digest.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception: return False

def token_for(user: User) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user.id), "iat": now, "exp": now + timedelta(days=7)}, SECRET, algorithm=ALGORITHM)

bearer = HTTPBearer(auto_error=False)
def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(db_dep)):
    if not creds: raise HTTPException(401, "Entre na sua conta para continuar.")
    try: uid = int(jwt.decode(creds.credentials, SECRET, algorithms=[ALGORITHM])["sub"])
    except (JWTError, ValueError, KeyError): raise HTTPException(401, "Sessão inválida. Entre novamente.")
    user = db.get(User, uid)
    if not user or not user.active: raise HTTPException(401, "Conta indisponível.")
    return user

def serialize(obj):
    data = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}
    for k, v in data.items():
        if isinstance(v, datetime): data[k] = v.isoformat()
    data.pop("password_hash", None)
    return data

app = FastAPI(title="Quantum Hub API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    email = os.getenv("ADMIN_EMAIL")
    password = os.getenv("ADMIN_PASSWORD")
    if email and password:
        with SessionLocal() as db:
            existing = db.query(User).filter(func.lower(User.email) == email.lower()).first()
            if not existing:
                db.add(User(name="Administrador", email=email.lower(), password_hash=hash_password(password), role="admin"))
                db.commit()

@app.get("/api/health")
def health():
    with SessionLocal() as db: db.execute(func.now())
    return {"status": "ok", "app": "Quantum Hub"}

@app.post("/api/auth/register")
def register(payload: RegisterIn, db: Session = Depends(db_dep)):
    email = payload.email.lower()
    if db.query(User).filter(func.lower(User.email) == email).first(): raise HTTPException(409, "Este e-mail já está cadastrado.")
    role = "admin" if db.query(User).count() == 0 else "member"
    user = User(name=payload.name.strip(), email=email, password_hash=hash_password(payload.password), role=role)
    db.add(user); db.commit(); db.refresh(user)
    return {"token": token_for(user), "user": serialize(user)}

@app.post("/api/auth/login")
def login(payload: LoginIn, db: Session = Depends(db_dep)):
    user = db.query(User).filter(func.lower(User.email) == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.password_hash): raise HTTPException(401, "E-mail ou senha incorretos.")
    if not user.active: raise HTTPException(403, "Conta desativada.")
    return {"token": token_for(user), "user": serialize(user)}

@app.get("/api/me")
def me(user: User = Depends(current_user)): return serialize(user)

@app.patch("/api/me")
def update_me(payload: ProfileIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    user.name = payload.name.strip(); db.commit(); db.refresh(user); return serialize(user)

@app.get("/api/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    projects = db.query(Project).filter(Project.owner_id == user.id).count()
    tasks = db.query(Task).filter(Task.owner_id == user.id).count()
    done = db.query(Task).filter(Task.owner_id == user.id, Task.status == "done").count()
    notes = db.query(Note).filter(Note.owner_id == user.id).count()
    recent = db.query(Task).filter(Task.owner_id == user.id).order_by(Task.created_at.desc()).limit(5).all()
    return {"projects": projects, "tasks": tasks, "completed": done, "notes": notes, "recent_tasks": [serialize(x) for x in recent]}

@app.get("/api/projects")
def projects(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    return [serialize(x) for x in db.query(Project).filter(Project.owner_id == user.id).order_by(Project.created_at.desc()).all()]
@app.post("/api/projects")
def create_project(p: ProjectIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj = Project(**p.model_dump(), owner_id=user.id); db.add(obj); db.commit(); db.refresh(obj); return serialize(obj)
@app.patch("/api/projects/{item_id}")
def edit_project(item_id: int, p: ProjectIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj = db.query(Project).filter(Project.id == item_id, Project.owner_id == user.id).first()
    if not obj: raise HTTPException(404, "Projeto não encontrado.")
    for k,v in p.model_dump().items(): setattr(obj,k,v)
    db.commit(); db.refresh(obj); return serialize(obj)
@app.delete("/api/projects/{item_id}")
def delete_project(item_id: int, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj = db.query(Project).filter(Project.id == item_id, Project.owner_id == user.id).first()
    if not obj: raise HTTPException(404, "Projeto não encontrado.")
    db.delete(obj); db.commit(); return {"ok": True}

@app.get("/api/tasks")
def tasks(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    return [serialize(x) for x in db.query(Task).filter(Task.owner_id == user.id).order_by(Task.created_at.desc()).all()]
@app.post("/api/tasks")
def create_task(p: TaskIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    data=p.model_dump()
    if data["project_id"] and not db.query(Project).filter(Project.id==data["project_id"], Project.owner_id==user.id).first(): raise HTTPException(404,"Projeto inválido.")
    obj=Task(**data, owner_id=user.id); db.add(obj); db.commit(); db.refresh(obj); return serialize(obj)
@app.patch("/api/tasks/{item_id}")
def edit_task(item_id: int, p: TaskIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj=db.query(Task).filter(Task.id==item_id, Task.owner_id==user.id).first()
    if not obj: raise HTTPException(404,"Tarefa não encontrada.")
    for k,v in p.model_dump().items(): setattr(obj,k,v)
    db.commit(); db.refresh(obj); return serialize(obj)
@app.delete("/api/tasks/{item_id}")
def delete_task(item_id: int, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj=db.query(Task).filter(Task.id==item_id, Task.owner_id==user.id).first()
    if not obj: raise HTTPException(404,"Tarefa não encontrada.")
    db.delete(obj); db.commit(); return {"ok":True}

@app.get("/api/notes")
def notes(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    return [serialize(x) for x in db.query(Note).filter(Note.owner_id==user.id).order_by(Note.updated_at.desc()).all()]
@app.post("/api/notes")
def create_note(p: NoteIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj=Note(**p.model_dump(), owner_id=user.id); db.add(obj); db.commit(); db.refresh(obj); return serialize(obj)
@app.patch("/api/notes/{item_id}")
def edit_note(item_id: int, p: NoteIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj=db.query(Note).filter(Note.id==item_id, Note.owner_id==user.id).first()
    if not obj: raise HTTPException(404,"Nota não encontrada.")
    obj.title=p.title; obj.content=p.content; db.commit(); db.refresh(obj); return serialize(obj)
@app.delete("/api/notes/{item_id}")
def delete_note(item_id: int, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj=db.query(Note).filter(Note.id==item_id, Note.owner_id==user.id).first()
    if not obj: raise HTTPException(404,"Nota não encontrada.")
    db.delete(obj); db.commit(); return {"ok":True}

@app.get("/api/notifications")
def notifications(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    return [serialize(x) for x in db.query(Notification).filter(Notification.owner_id==user.id).order_by(Notification.created_at.desc()).limit(50).all()]
@app.patch("/api/notifications/{item_id}/read")
def read_notification(item_id: int, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    obj=db.query(Notification).filter(Notification.id==item_id, Notification.owner_id==user.id).first()
    if not obj: raise HTTPException(404,"Notificação não encontrada.")
    obj.read=True; db.commit(); return {"ok":True}

@app.get("/api/admin/users")
def admin_users(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    if user.role != "admin": raise HTTPException(403,"Acesso restrito ao administrador.")
    return [serialize(x) for x in db.query(User).order_by(User.created_at.desc()).all()]
@app.patch("/api/admin/users/{item_id}/active")
def admin_toggle_user(item_id: int, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    if user.role != "admin": raise HTTPException(403,"Acesso restrito ao administrador.")
    target=db.get(User,item_id)
    if not target: raise HTTPException(404,"Usuário não encontrado.")
    if target.id == user.id: raise HTTPException(400,"Você não pode desativar sua própria conta.")
    target.active=not target.active; db.commit(); return {"active":target.active}

frontend_dir = Path(__file__).parent / "static"
if frontend_dir.exists():
    app.mount("/assets", StaticFiles(directory=frontend_dir / "assets"), name="assets")
    @app.get("/{full_path:path}")
    def frontend(full_path: str):
        candidate = frontend_dir / full_path
        if full_path and candidate.is_file() and frontend_dir in candidate.parents: return FileResponse(candidate)
        return FileResponse(frontend_dir / "index.html")
