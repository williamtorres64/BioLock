"""Etapas de processamento da imagem usada no reconhecimento facial."""

import cv2
import numpy as np
import face_recognition

class BiometricVisionPipeline:
    def __init__(self, authorized_database):
        """Inicializa o processamento com as pessoas autorizadas."""
        self.authorized_database = authorized_database

    def acquire_frame_from_bytes(self, image_bytes: bytes) -> np.ndarray:
        """Etapa 1: recebe os bytes da imagem e monta um quadro."""
        np_arr = np.frombuffer(image_bytes, np.uint8)
        frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        return frame

    def preprocess_image(self, frame: np.ndarray) -> np.ndarray:
        """Etapa 2: converte a imagem para o formato esperado pelo reconhecimento facial."""
        if frame is None:
            raise ValueError("Não foi possível ler a imagem recebida.")
        
        # A biblioteca de reconhecimento trabalha com imagens RGB.
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        return rgb_frame

    def segment_faces(self, rgb_frame: np.ndarray):
        """Etapa 3: encontra os rostos presentes no quadro."""
        face_locations = face_recognition.face_locations(rgb_frame, model="hog")
        return face_locations

    def extract_features(self, rgb_frame: np.ndarray, face_locations):
        """Etapa 4: transforma as caracteristicas do rosto em um vetor numerico."""
        if not face_locations:
            return []
        
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
        return face_encodings

    def classify_and_interpret(self, unknown_encoding, tolerance: float = 0.3):
        """Etapa 5: compara o rosto capturado com os cadastros autorizados."""
        lowest_distance = None
        for username, data in self.authorized_database.items():
            reference_encoding = data.get("encoding")
            if reference_encoding is not None:
                face_distance = float(face_recognition.face_distance([reference_encoding], unknown_encoding)[0])
                if lowest_distance is None or face_distance < lowest_distance:
                    lowest_distance = face_distance

                matches = face_recognition.compare_faces([reference_encoding], unknown_encoding, tolerance=tolerance)
                if matches[0]:
                    return {
                        "authenticated": True,
                        "username": username,
                        "name": data["name"],
                        "security_level": data["level"],
                        "confidence_score": float(1.0 - face_distance)
                    }

        return {
            "authenticated": False,
            "confidence_score": None if lowest_distance is None else float(1.0 - lowest_distance),
            "message": "Acesso recusado: o rosto não corresponde a nenhum cadastro autorizado."
        }

    def process_full_pipeline(self, image_bytes: bytes):
        """Executa as cinco etapas de verificação em sequência."""
        # Etapa 1: recebimento da imagem.
        raw_frame = self.acquire_frame_from_bytes(image_bytes)
        
        # Etapa 2: preparacao da imagem.
        rgb_frame = self.preprocess_image(raw_frame)
        
        # Etapa 3: localizacao dos rostos.
        face_locations = self.segment_faces(rgb_frame)
        if not face_locations:
            return {"authenticated": False, "message": "Nenhum rosto foi encontrado na imagem."}
        
        # Etapa 4: extracao das caracteristicas.
        face_encodings = self.extract_features(rgb_frame, face_locations)
        if not face_encodings:
            return {"authenticated": False, "message": "Não foi possível analisar as características do rosto."}
        
        # Etapa 5: comparacao com o cadastro.
        result = self.classify_and_interpret(face_encodings[0])
        return result
