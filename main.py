from auth import create_access_token, get_current_user
from config import BRANDS_COLUMN, GOOGLE_CREDENTIALS, SHEET_NAME, SPREADSHEET_ID
from slowapi import Limiter
from google.oauth2.service_account import Credentials
from slowapi.util import get_remote_address
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from googleapiclient.discovery import build
from pydantic import BaseModel

from datetime import timedelta
from config import JWT_EXPIRATION_MINUTES, ADMIN_USERNAME, ADMIN_PASSWORD

# Crear la app de FastAPI
app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Modelo del token
class Token(BaseModel):
    access_token: str
    token_type: str


# Endpoint para obtener el token
@app.post("/login", response_model=Token)
@limiter.limit("5/minute")  # Máximo 5 solicitudes por minuto
async def get_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != ADMIN_USERNAME or form_data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Crear token
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=timedelta(minutes=JWT_EXPIRATION_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoint para consultar datos
@app.get("/brands", dependencies=[Depends(get_current_user)])
@limiter.limit("5/minute")  # Permite 5 solicitudes por minuto por IP
async def get_unique_brands(
    request: Request,
):  # Agrego request para que slowapi pueda obtener la IP y limitar las solicitudes
    try:
        # Construir servicio
        credentials = Credentials.from_service_account_info(GOOGLE_CREDENTIALS)
        service = build("sheets", "v4", credentials=credentials)
        sheet = service.spreadsheets()
        # Leer datos de la hoja
        result = (
            sheet.values().get(spreadsheetId=SPREADSHEET_ID, range=SHEET_NAME).execute()
        )
        values = result.get("values", [])
        if not values:
            return {"message": "No se encontraron datos."}

        # Extraer el índice de la columna "Marcas"
        headers = values[0]  # Primera fila contiene los encabezados
        if BRANDS_COLUMN not in headers:
            raise HTTPException(
                status_code=400,
                detail=f"Columna '{BRANDS_COLUMN}' no encontrada en el archivo.",
            )

        column_index = headers.index(BRANDS_COLUMN)

        # Extraer las marcas y devolver los valores únicos
        brands = {row[column_index] for row in values[1:] if len(row) > column_index}
        return {"brands": sorted(list(brands))}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
