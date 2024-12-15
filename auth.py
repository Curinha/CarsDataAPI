# Funciones de autenticación
from datetime import datetime, timedelta

import jwt
from config import JWT_ALGORITHM, JWT_SECRET

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Función para crear el token JWT
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# Validar un token JWT
def decode_access_token(token: str):
    try:
        payload = jwt.decode(
            token, JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )  # Verifica la firma!
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Invalid token")


# Dependency para obtener el usuario desde el token
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    return payload  # Puedes acceder a los datos del token, como user_id
