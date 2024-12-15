from auth import create_access_token, verify_token
from config import BRANDS_COLUMN, GOOGLE_CREDENTIALS, SHEET_NAME, SPREADSHEET_ID
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from googleapiclient.discovery import build
from pydantic import BaseModel

from datetime import timedelta
from config import JWT_EXPIRATION_MINUTES, ADMIN_USERNAME, ADMIN_PASSWORD

# Crear la app de FastAPI
app = FastAPI()
limiter = Limiter(key_func=get_remote_address, default_limits=["5/minute"])
app.state.limiter = limiter

# Modelo del token
class Token(BaseModel):
    access_token: str
    token_type: str

# Limite de peticiones global
@app.middleware("http")
async def add_rate_limiter(request: Request, call_next):
    with limiter.key(request.client.host):
        return await call_next(request)

# Endpoint para obtener el token
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != ADMIN_USERNAME or form_data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Crear token
    access_token = create_access_token(
        data={"sub": form_data.username},
        expires_delta=timedelta(minutes=JWT_EXPIRATION_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoint para obtener la lista de marcas
@app.get("/brands")
async def get_unique_brands(verified_token: dict = Depends(verify_token)):
    try:
        # Construir servicio de Google Sheets
        service = build("sheets", "v4", credentials=GOOGLE_CREDENTIALS)
        sheet = service.spreadsheets()
        result = (
            sheet.values().get(spreadsheetId=SPREADSHEET_ID, range=SHEET_NAME).execute()
        )
        values = result.get("values", [])
        if not values:
            return {"message": "No se encontraron datos."}

        headers = values[0]
        if BRANDS_COLUMN not in headers:
            raise HTTPException(
                status_code=400, detail=f"Columna '{BRANDS_COLUMN}' no encontrada"
            )

        column_index = headers.index(BRANDS_COLUMN)
        brands = {row[column_index] for row in values[1:] if len(row) > column_index}
        return {"brands": sorted(list(brands))}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
