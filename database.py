"""Modelos e conexao com o banco de dados do BioLock."""

import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Text, Boolean, inspect, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

# Arquivo do banco de dados.
DB_PATH = "vault_security.db"
DB_URL = f"sqlite:///{DB_PATH}"

# Motor do SQLAlchemy e fabrica de sessoes.
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    """Representa uma pessoa cadastrada no sistema e seu nível de acesso."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)
    access_level = Column(Integer, nullable=False, default=1)  # 1 a 3: usuários; 100: administrador
    approved = Column(Boolean, nullable=False, default=False, server_default=text("0"))
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Cada pessoa possui uma referência biométrica e vários registros de acesso.
    biometric_profile = relationship("BiometricProfile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


class BiometricProfile(Base):
    """
    Guarda a representação numérica do rosto usada na verificação.
    """
    __tablename__ = "biometric_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    encoding_data = Column(Text, nullable=False)
    image_path = Column(String(255), nullable=True)
    registered_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="biometric_profile")


class AuditLog(Base):
    """Registra todas as tentativas de acesso e o resultado da verificação."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    attempt_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    access_granted = Column(Boolean, nullable=False)
    confidence_score = Column(Float, nullable=True)
    ip_address = Column(String(45), nullable=True)
    failure_reason = Column(String(255), nullable=True)

    user = relationship("User", back_populates="audit_logs")


def init_db():
    """Cria as tabelas caso elas ainda não existam."""
    Base.metadata.create_all(bind=engine)
    user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
    if "approved" not in user_columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE users ADD COLUMN approved BOOLEAN NOT NULL DEFAULT 0"))
    print(f"[BANCO] Banco SQLite inicializado em '{DB_PATH}'")


def get_db():
    """Fornece uma sessão do banco para cada requisição."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
