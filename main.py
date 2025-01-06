import base64
from datetime import timedelta

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi
from fastapi.templating import Jinja2Templates
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth import create_access_token, decode_access_token, get_current_user
from config import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    BRANDS_COLUMN,
    GOOGLE_CREDENTIALS,
    ID_COLUMN,
    JWT_EXPIRATION_MINUTES,
    SHEET_BRANDS,
    SPREADSHEET_ID,
)

# Crear la app de FastAPI
app = FastAPI(
    title="TengoLugarCarsAPI",  # Set custom title
    description="API for consulting DNRPA cars data",  # Optional description
    version="1.0.0",  # Optional version
    openapi_url="/openapi.json",
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
# Configurar directorio de recursos estáticos
app.mount("/static", StaticFiles(directory="static"), name="static")

# Configurar plantillas con Jinja2
templates = Jinja2Templates(directory="templates")


# Modelo del token
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


######## Login GET #########
@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


######## Login POST #########
@app.post("/login", response_model=Token, include_in_schema=False)
@limiter.limit("5/minute")
async def get_access_token(request: Request):

    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Missing or invalid Basic Auth header")

    # Extraer y decodificar credenciales
    encoded_credentials = auth_header.split(" ")[1]  # Obtener la parte después de "Basic "
    decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
    
    # Separar username y password
    username, password = decoded_credentials.split(":", 1)
    
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Crear access token
    access_token = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=JWT_EXPIRATION_MINUTES),
    )

    # Crear refresh token
    refresh_token = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(days=1),  # Refresh token válido por 1 día
    )

    # Verificar el Accept Header para decidir la respuesta
    accept_header = request.headers.get("Accept", "").lower()

    if "text/html" in accept_header:
        # Redirigir a /docs con el token en la URL
        response = RedirectResponse(url=f"/docs?token={access_token}", status_code=303)
        return response

    # Si es una API o WebApp consumiendo JSON, devolver los tokens
    return JSONResponse(
        content={
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        },
        status_code=200,
    )


# Endpoint para refrescar el token de acceso
@app.post("/refresh", response_model=Token, include_in_schema=False)
@limiter.limit("5/minute")
async def refresh_access_token(
    request: Request,
    token: str = Body(...),  # Recibe el refresh token como entrada
):
    # Decodificar y validar el refresh token
    payload = decode_access_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Crear un nuevo access token
    new_access_token = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=JWT_EXPIRATION_MINUTES),
    )
    return {"access_token": new_access_token, "token_type": "bearer"}


# Endpoint para consultar datos
@app.get(
    "/brands",
    tags=["Brands"],
    operation_id="getUniqueBrands",
    dependencies=[Depends(get_current_user)],
)
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
            sheet.values()
            .get(spreadsheetId=SPREADSHEET_ID, range=SHEET_BRANDS)
            .execute()
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
        elif ID_COLUMN not in headers:
            raise HTTPException(
                status_code=400,
                detail=f"Columna '{ID_COLUMN}' no encontrada en el archivo.",
            )

        # Obtener los índices de las columnas requeridas
        brand_index = headers.index(BRANDS_COLUMN)
        id_index = headers.index(ID_COLUMN)

        # Procesar las filas restantes y construir la lista de diccionarios
        brands_list = []
        for row in values[1:]:  # Excluir encabezados
            # Evitar errores si la fila no tiene suficientes columnas
            if len(row) > max(brand_index, id_index):
                brand = row[brand_index]
                id_value = int(row[id_index])
                brands_list.append({"id": id_value, "name": brand})
        return brands_list
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
