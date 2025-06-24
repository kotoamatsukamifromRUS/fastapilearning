from fastapi import Depends, status, Response, Cookie, Request
from fastapi.security import (
    HTTPBasicCredentials,
    HTTPBasic,
    OAuth2PasswordBearer,
)
from fastapi.exceptions import HTTPException
import jwt
from passlib.context import CryptContext
import datetime


import secrets

# files
from db import get_user_from_db, open_db, save_refresh_token_to_db
from models import UserInDB

# settings
from settings import (
    DB_REFRESH_TOKENS,
    SECRET_KEY,
    ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_MINUTES,
    JWT_decode_method,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

security = HTTPBasic()
pwd_context = CryptContext(
    schemes=["bcrypt"],
    bcrypt__rounds=4,
    deprecated="auto",
)


def create_jwt_token(data: dict, type: str) -> str:
    to_encode = data.copy()
    if type == "REFRESH":
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES
        )
        to_encode.update({"exp": expire, "type": type})
        token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        save_refresh_token_to_db(data, new_token=token)
        return token
    elif type == "ACCESS":
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
        to_encode.update({"exp": expire, "type": type})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    else:
        raise HTTPException(status_code=401, detail="ошибка названия вида токена")


def decode_jwt(token: str):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_token
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(
            status_code=401,
            detail="ошибка истечения срока действия токена",
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"{e},ошибки декодирования токена")


def decode_jwt_from_Header(token: str = Depends(oauth2_scheme)):
    decoded_token = decode_jwt(token)
    if decoded_token["type"] != "ACCESS":
        raise HTTPException(status_code=404, detail="не тот тип токена")
    return decoded_token["sub"]


# способы получения токена из куки
# def decode_jwt_from_Cookie(access_token: str = Cookie()):
#    print(access_token)
#    return decode_jwt(access_token)


def decode_jwt_from_Cookie(request: Request):
    access_token = request.cookies.get("access_token")
    if access_token is None:
        raise HTTPException(status_code=403, detail=f"Истечение срока действия куки")
    decoded_token = decode_jwt(access_token)
    if decoded_token["type"] != "ACCESS":
        raise HTTPException(status_code=404, detail="не тот тип токена")
    return decoded_token["sub"]


# способ декодирования jwt токена. Куки или заголовок
try:
    decode_jwt_method = {
        "cookie": decode_jwt_from_Cookie,
        "headers": decode_jwt_from_Header,
    }[JWT_decode_method]
except:
    decode_jwt_method = decode_jwt_from_Cookie


def validate_refresh_token(token: str, response: Response):
    try:
        coded_token = token
        token = decode_jwt(coded_token)
        username = token["sub"]
        if token["type"] != "REFRESH":
            raise TypeError("Тип токена не REFRESH")
        cur_db = open_db(DB_REFRESH_TOKENS)
        if secrets.compare_digest(cur_db[username], coded_token):
            access_token = create_jwt_token({"sub": username}, type="ACCESS")
            refresh_token = create_jwt_token({"sub": username}, type="REFRESH")
            response.set_cookie(
                key="Authorization", value=access_token, httponly=True, secure=True
            )
            return {
                "access_token": f"Bearer {access_token}",
                "refresh_token": refresh_token,
            }
        raise jwt.ExpiredSignatureError
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail=f"ошибка декодирования токена")
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(
            status_code=401,
            detail="ошибка истечения срока действия REFRESH токена. Залогинтесь заново",
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"{e}")


def auth_user(credentials: HTTPBasicCredentials = Depends(security)) -> UserInDB:
    user = get_user_from_db(credentials.username)
    if user is None or not pwd_context.verify(
        credentials.password, user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user
