"""Cria o primeiro administrador aprovado do BioLock."""

import argparse
import getpass
from pathlib import Path

import cv2
import face_recognition
import numpy as np

from database import BiometricProfile, SessionLocal, User, init_db
from main import hash_password


def main():
    parser = argparse.ArgumentParser(description="Cria um administrador BioLock com acesso total.")
    parser.add_argument("username")
    parser.add_argument("full_name")
    parser.add_argument("image", type=Path, help="Caminho de uma imagem nítida com apenas um rosto")
    args = parser.parse_args()

    password = getpass.getpass("Senha do administrador: ")
    if not password:
        raise SystemExit("A senha não pode ficar vazia.")

    image = cv2.imread(str(args.image))
    if image is None:
        raise SystemExit("Não foi possível ler a imagem do administrador.")

    rgb_image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    locations = face_recognition.face_locations(rgb_image)
    if len(locations) != 1:
        raise SystemExit("A imagem precisa ter exatamente um rosto reconhecivel.")

    encodings = face_recognition.face_encodings(rgb_image, locations)
    if not encodings:
        raise SystemExit("Não foi possível analisar o rosto do administrador.")

    init_db()
    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.username == args.username).first()
        if existing_user:
            raise SystemExit("Esse identificador ja esta cadastrado.")

        user = User(
            username=args.username.strip(),
            full_name=args.full_name.strip(),
            password_hash=hash_password(password),
            access_level=100,
            approved=True,
            is_active=True,
        )
        db.add(user)
        db.flush()
        db.add(BiometricProfile(
            user_id=user.id,
            encoding_data=",".join(map(str, encodings[0])),
            image_path=str(args.image),
        ))
        db.commit()
        print(f"Administrador '{user.username}' criado com sucesso.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
