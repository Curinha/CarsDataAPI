# Configuración de variables de entorno y constantes
import os
from dotenv import load_dotenv

load_dotenv(override=True)

# Variables de entorno
GOOGLE_CREDENTIALS = {
    "type": os.getenv("GOOGLE_TYPE"),
    "project_id": os.getenv("GOOGLE_PROJECT_ID"),
    "private_key_id": os.getenv("GOOGLE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("GOOGLE_PRIVATE_KEY", "").replace("\\n", "\n"),  # Fix formatting
    "client_email": os.getenv("GOOGLE_CLIENT_EMAIL"),
    "auth_uri": os.getenv("GOOGLE_AUTH_URI"),
    "token_uri": os.getenv("GOOGLE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("GOOGLE_AUTH_PROVIDER_X509_CERT_URL", "https://www.googleapis.com/oauth2/v1/certs"),
    "client_x509_cert_url": os.getenv("GOOGLE_CLIENT_X509_CERT_URL"),
}
SPREADSHEET_ID = os.getenv("GOOGLE_SHEETS_ID")

# Configuración JWT
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")
JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES"))

# Variables estáticas
SHEET_MODELS = "Models"
SHEET_BRANDS = "Brands"
SHEET_DATA = "Data"

MODEL_ID_COLUMN = "model_id"
BRAND_ID_COLUMN = "brand_id"
GROUP_ID_COLUMN = "group_id"
ID_COLUMN = "id"
NAME_COLUMN = "name"

