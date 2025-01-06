# Configuración de variables de entorno y constantes
import os
from dotenv import load_dotenv

load_dotenv()

# Variables de entorno
GOOGLE_CREDENTIALS = {
    "type": os.getenv("GOOGLE_TYPE"),
    "project_id": os.getenv("GOOGLE_PROJECT_ID"),
    "private_key_id": os.getenv("GOOGLE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("GOOGLE_PRIVATE_KEY").replace("\\n", "\n"),
    "client_email": os.getenv("GOOGLE_CLIENT_EMAIL"),
    "token_uri": os.getenv("GOOGLE_TOKEN_URI"),
}
SPREADSHEET_ID = os.getenv("GOOGLE_SHEETS_ID")

# Configuración JWT
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES"))

# Administradores
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", default="TengoLugar")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", default="supersecurepassword")

# Variables estáticas
SHEET_MODELS = "Modelos"
SHEET_BRANDS = "Marcas"
ID_COLUMN = "id"
BRANDS_COLUMN = "marca"
