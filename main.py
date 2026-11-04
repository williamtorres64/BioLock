"""Aplicacao principal do BioLock, com autenticacao e controle de acesso."""

import os
import base64
import hashlib
import hmac
import secrets
import numpy as np
import face_recognition
import cv2
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request, Form
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from database import init_db, get_db, User, BiometricProfile, AuditLog
from vision_pipeline import BiometricVisionPipeline

app = FastAPI(title="BioLock - Sistema de controle de acesso biometrico")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "cH45_Fallback-Secret_@7OV"),
    session_cookie="biolock_session",
    max_age=3600,
    same_site="strict",
    https_only=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
)

# Garante que as tabelas existam quando o servidor iniciar.
@app.on_event("startup")
def startup_event():
    init_db()
    print("[BANCO] Banco inicializado. O sistema esta pronto para novos cadastros.")


def load_database_registry(db: Session) -> dict:
    """Carrega os cadastros biométricos ativos para a verificação facial."""
    registry = {}
    profiles = db.query(BiometricProfile).join(User).filter(User.is_active == True).all()
    
    for profile in profiles:
        user = profile.user
        try:
            encoding_array = np.array([float(x) for x in profile.encoding_data.split(",")])
            registry[user.username] = {
                "user_id": user.id,
                "name": user.full_name,
                "level": user.access_level,
                "encoding": encoding_array
            }
        except Exception as e:
            print(f"[ERRO] Não foi possível carregar o cadastro de {user.username}: {e}")
            
    return registry


class LoginPayload(BaseModel):
    username: str
    password: str
    image_data: str  # Imagem JPEG codificada, capturada pela câmera do navegador.


class RegisterPayload(BaseModel):
    username: str
    full_name: str
    password: str
    access_level: int = 1
    image_data: str


class AdminSetupPayload(BaseModel):
    username: str
    full_name: str
    password: str
    image_data: str


class UserUpdatePayload(BaseModel):
    full_name: Optional[str] = None
    access_level: Optional[int] = None
    approved: Optional[bool] = None
    is_active: Optional[bool] = None


def hash_password(password: str) -> str:
    """Gera um hash PBKDF2-SHA256 com salt para guardar a senha."""
    iterations = 600_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Confere a senha informada com o hash guardado."""
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def get_authenticated_session(request: Request, db: Session, minimum_level: int = 1) -> User:
    """Retorna a pessoa autenticada ou recusa uma sessão sem permissão."""
    session = request.session
    if not session.get("authenticated"):
        raise HTTPException(status_code=401, detail="É necessário fazer login.")

    user_id = session.get("user_id")
    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if user is None or not user.approved or user.access_level < minimum_level:
        session.clear()
        raise HTTPException(status_code=403, detail="Você não possui permissão para esta área.")

    return user


@app.get("/", response_class=HTMLResponse)
async def read_root(db: Session = Depends(get_db)):
    """Exibe a configuração inicial ou a página principal do sistema."""
    admin_exists = db.query(User).filter(User.access_level == 100).first() is not None
    if not admin_exists:
        return RedirectResponse(url="/static/admin-setup.html?modo=primeiro", status_code=303)

    with open("static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)


@app.post("/api/authenticate")
async def authenticate_face(request: Request, payload: LoginPayload, db: Session = Depends(get_db)):
    """Confere senha e rosto e registra o resultado da tentativa de acesso."""
    client_ip = request.client.host if request.client else "desconhecido"
    
    try:
        username = payload.username.strip()
        user = db.query(User).filter(User.username == username, User.is_active == True).first()
        if user is None or not verify_password(payload.password, user.password_hash):
            db.add(AuditLog(
                user_id=user.id if user else None,
                access_granted=False,
                ip_address=client_ip,
                failure_reason="Identificador ou senha invalidos"
            ))
            db.commit()
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "Identificador ou senha invalidos."}
            )

        if not user.approved:
            db.add(AuditLog(
                user_id=user.id,
                access_granted=False,
                ip_address=client_ip,
                failure_reason="A conta aguarda aprovacao do administrador"
            ))
            db.commit()
            return JSONResponse(
                status_code=403,
                content={"success": False, "message": "Sua conta ainda aguarda aprovacao do administrador."}
            )

        authorized_registry = load_database_registry(db)
        authorized_registry = {
            username: authorized_registry[username]
        } if username in authorized_registry else {}
        if not authorized_registry:
            return JSONResponse(
                status_code=503, 
                content={"success": False, "message": "Não existe um cadastro biométrico para este usuário."}
            )

        vision_pipeline = BiometricVisionPipeline(authorized_registry)

        # Decodifica a imagem enviada pela câmera.
        header, encoded = payload.image_data.split(",", 1) if "," in payload.image_data else ("", payload.image_data)
        image_bytes = base64.b64decode(encoded)

        # Executa as etapas de verificação facial.
        result = vision_pipeline.process_full_pipeline(image_bytes)

        if not result.get("authenticated"):
                # Registra a tentativa de acesso recusada.
            failure_log = AuditLog(
                user_id=user.id,
                access_granted=False,
                confidence_score=result.get("confidence_score"),
                ip_address=client_ip,
                failure_reason=result.get("message", "O rosto não foi reconhecido")
            )
            db.add(failure_log)
            db.commit()

            return JSONResponse(
                status_code=403, 
                content={"success": False, "message": result.get("message", "Acesso recusado.")}
            )

        # Rosto e credenciais conferidos.
        matched_username = result["username"]
        user_data = authorized_registry[matched_username]
        user_id = user_data["user_id"]
        level = result["security_level"]
        confidence = result["confidence_score"]

        # Registra o acesso autorizado.
        success_log = AuditLog(
            user_id=user_id,
            access_granted=True,
            confidence_score=confidence,
            ip_address=client_ip,
            failure_reason=None
        )
        db.add(success_log)
        db.commit()

        request.session.clear()
        request.session.update({
            "authenticated": True,
            "user_id": user_id,
            "username": matched_username,
            "access_level": level,
        })

        return JSONResponse(content={
            "success": True,
            "name": result["name"],
            "security_level": level,
            "confidence_score": confidence,
            "redirect_url": "/static/admin.html" if level == 100 else f"/static/level{level}.html"
        })

    except Exception as e:
        error_log = AuditLog(
            user_id=None,
            access_granted=False,
            confidence_score=None,
            ip_address=client_ip,
            failure_reason=f"Erro interno do servidor: {str(e)}"
        )
        db.add(error_log)
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/register")
async def register_biometric_user(
    payload: RegisterPayload,
    db: Session = Depends(get_db)
):
    """Cadastra uma pessoa e sua referência facial no banco de dados."""
    try:
        username = payload.username.strip()
        full_name = payload.full_name.strip()
        access_level = payload.access_level
        image_data = payload.image_data

        if access_level not in (1, 2, 3):
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "O nível solicitado deve ser 1, 2 ou 3."}
            )

        # Evita duplicar identificadores.
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            return JSONResponse(status_code=400, content={"success": False, "message": "Esse identificador ja esta cadastrado."})

        # Decodifica o quadro capturado pela câmera.
        if "," in image_data:
            header, encoded = image_data.split(",", 1)
        else:
            encoded = image_data
            
        image_bytes = base64.b64decode(encoded)
        np_arr = np.frombuffer(image_bytes, np.uint8)
        frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if frame is None:
            return JSONResponse(status_code=400, content={"success": False, "message": "A imagem enviada não pode ser lida."})

        # Localiza e analisa o rosto da pessoa.
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)
        
        if not face_locations:
            return JSONResponse(status_code=400, content={"success": False, "message": "Nenhum rosto foi encontrado. Tente melhorar a iluminacao."})
        
        if len(face_locations) > 1:
            return JSONResponse(status_code=400, content={"success": False, "message": "Foram encontrados varios rostos. O cadastro precisa de apenas uma pessoa."})

        encodings = face_recognition.face_encodings(rgb_frame, face_locations)
        if not encodings:
            return JSONResponse(status_code=400, content={"success": False, "message": "Não foi possível analisar as características do rosto."})

        face_encoding_str = ",".join(map(str, encodings[0]))

        # Cria a conta ainda pendente de aprovacao.
        new_user = User(
            username=username,
            full_name=full_name,
            password_hash=hash_password(payload.password),
            access_level=access_level,
            approved=False,
            is_active=True
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Guarda a referência facial ligada à conta.
        new_profile = BiometricProfile(
            user_id=new_user.id,
            encoding_data=face_encoding_str,
            image_path=None
        )
        db.add(new_profile)
        db.commit()

        return JSONResponse(content={
            "success": True,
            "message": f"Cadastro de {full_name} enviado com sucesso. Nível solicitado: {access_level}."
        })

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/setup-admin")
async def setup_admin(
    request: Request,
    payload: AdminSetupPayload,
    db: Session = Depends(get_db),
):
    """Cria o primeiro administrador ou outro administrador autorizado."""
    admin_exists = db.query(User).filter(User.access_level == 100).first() is not None
    if admin_exists:
        get_authenticated_session(request, db, minimum_level=100)

    username = payload.username.strip()
    full_name = payload.full_name.strip()
    if not username or not full_name or len(payload.password) < 8:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Preencha os dados e use uma senha com pelo menos 8 caracteres."},
        )

    if db.query(User).filter(User.username == username).first():
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Esse nome de usuário já está cadastrado."},
        )

    try:
        encoded = payload.image_data.split(",", 1)[-1]
        image_bytes = base64.b64decode(encoded)
        image_array = np.frombuffer(image_bytes, np.uint8)
        frame = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        if frame is None:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "A imagem enviada não pode ser lida."},
            )

        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        face_locations = face_recognition.face_locations(rgb_frame)
        if len(face_locations) != 1:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "A imagem precisa mostrar exatamente um rosto."},
            )

        encodings = face_recognition.face_encodings(rgb_frame, face_locations)
        if not encodings:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Não foi possível analisar o rosto informado."},
            )

        admin = User(
            username=username,
            full_name=full_name,
            password_hash=hash_password(payload.password),
            access_level=100,
            approved=True,
            is_active=True,
        )
        db.add(admin)
        db.flush()
        db.add(BiometricProfile(
            user_id=admin.id,
            encoding_data=",".join(map(str, encodings[0])),
            image_path=None,
        ))
        db.commit()
        return JSONResponse(content={
            "success": True,
            "message": "Administrador cadastrado e aprovado com sucesso.",
        })
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/session")
async def read_session(request: Request, db: Session = Depends(get_db)):
    """Retorna os dados básicos da sessão, sem expor credenciais."""
    user = get_authenticated_session(request, db)
    return {
        "authenticated": True,
        "username": user.username,
        "access_level": user.access_level,
        "approved": user.approved,
    }


@app.post("/api/logout")
@app.get("/api/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)


@app.get("/api/admin/users")
async def list_users(request: Request, db: Session = Depends(get_db)):
    """Lista as contas sem expor senhas ou referências biométricas."""
    get_authenticated_session(request, db, minimum_level=100)
    users = db.query(User).order_by(User.id).all()
    return {
        "users": [
            {
                "id": user.id,
                "username": user.username,
                "full_name": user.full_name,
                "access_level": user.access_level,
                "approved": user.approved,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat(),
            }
            for user in users
        ]
    }


@app.get("/api/admin/logs")
async def list_audit_logs(request: Request, db: Session = Depends(get_db)):
    """Lista as tentativas de acesso para consulta do administrador."""
    get_authenticated_session(request, db, minimum_level=100)
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.attempt_timestamp.desc())
        .limit(200)
        .all()
    )
    return {
        "logs": [
            {
                "id": log.id,
                "username": log.user.username if log.user else "Não identificado",
                "timestamp": log.attempt_timestamp.isoformat(),
                "access_granted": log.access_granted,
                "confidence_score": log.confidence_score,
                "ip_address": log.ip_address or "Não informado",
                "failure_reason": log.failure_reason,
            }
            for log in logs
        ]
    }


@app.patch("/api/admin/users/{user_id}")
async def update_user(
    user_id: int,
    payload: UserUpdatePayload,
    request: Request,
    db: Session = Depends(get_db),
):
    """Atualiza aprovacao, permissao, situacao ou nome de uma conta."""
    admin = get_authenticated_session(request, db, minimum_level=100)
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if user.id == admin.id and (
        payload.access_level is not None and payload.access_level != 100
        or payload.approved is False
        or payload.is_active is False
    ):
        raise HTTPException(status_code=400, detail="Um administrador não pode retirar o próprio acesso administrativo.")

    if payload.access_level is not None and payload.access_level not in (1, 2, 3, 100):
        raise HTTPException(status_code=400, detail="O nível de acesso deve ser 1, 2, 3 ou 100.")
    if payload.full_name is not None:
        full_name = payload.full_name.strip()
        if not full_name:
            raise HTTPException(status_code=400, detail="O nome completo não pode ficar vazio.")
        user.full_name = full_name
    if payload.access_level is not None:
        user.access_level = payload.access_level
    if payload.approved is not None:
        user.approved = payload.approved
    if payload.is_active is not None:
        user.is_active = payload.is_active

    db.commit()
    return {"success": True, "message": "Cadastro atualizado com sucesso."}


@app.get("/static/level1.html", response_class=HTMLResponse)
async def level_one_page(request: Request, db: Session = Depends(get_db)):
    get_authenticated_session(request, db, minimum_level=1)
    return FileResponse("static/level1.html")


@app.get("/static/level2.html", response_class=HTMLResponse)
async def level_two_page(request: Request, db: Session = Depends(get_db)):
    get_authenticated_session(request, db, minimum_level=2)
    return FileResponse("static/level2.html")


@app.get("/static/level3.html", response_class=HTMLResponse)
async def level_three_page(request: Request, db: Session = Depends(get_db)):
    get_authenticated_session(request, db, minimum_level=3)
    return FileResponse("static/level3.html")


@app.get("/static/admin.html", response_class=HTMLResponse)
async def admin_page(request: Request, db: Session = Depends(get_db)):
    get_authenticated_session(request, db, minimum_level=100)
    return FileResponse("static/admin.html")


# Keep login, registration, and shared assets public; protected pages are above this mount.
app.mount("/static", StaticFiles(directory="static"), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
