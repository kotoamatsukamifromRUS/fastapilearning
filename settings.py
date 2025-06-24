from dotenv import load_dotenv
import os
from pathlib import Path


# режим окржуения
def get_settings(setting):
    load_dotenv(Path(__file__).parent / "settings.env")
    try:
        return os.getenv(setting)
    except:
        raise


SECRET_KEY = get_settings("SECRET_KEY")
ALGORITHM = get_settings("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(get_settings("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_MINUTES = int(get_settings("REFRESH_TOKEN_EXPIRE_MINUTES"))
DB = get_settings("DB")
DB_resources = get_settings("DB_resources")
DB_REFRESH_TOKENS = get_settings("DB_REFRESH_TOKENS")
JWT_decode_method = get_settings("JWT_decode_method")
