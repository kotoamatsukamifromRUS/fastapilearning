import uvicorn as uvicorn
from fastapi import FastAPI, Depends, Request, Response
from fastapi.exceptions import HTTPException
from uuid import uuid4
from contextlib import asynccontextmanager
from slowapi import Limiter
from slowapi.util import get_remote_address
from settings import ACCESS_TOKEN_EXPIRE_MINUTES
from typing import Callable, Awaitable, Optional

# files
from dependencies import request_ctx_var, get_rate_limit_by_role
from models import UserInDB, User, RefreshToken, UserToSetRoles, Resourse_info
from rbac import PermissionChecker
from db import open_db, save_to_db
from security import (
    pwd_context,
    auth_user,
    create_jwt_token,
    decode_jwt_method,
    validate_refresh_token,
)
from settings import DB
from dependencies import change_role, know_the_args
from resources import (
    OwnershipCheck,
    get_resource,
    create_resource,
    put_info_to_resource,
    delete_resource,
)


# что происходит при закрытии приложения
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(lifespan=lifespan)
# лимиттер
limiter = Limiter(key_func=get_remote_address)


# включение request в переменную контекста
@app.middleware("http")
async def request_context_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    request_ctx = request_ctx_var.set(request)
    response = await call_next(request)
    request_ctx_var.reset(request_ctx)
    return response


@app.post("/register")
@limiter.limit("1/minute")
async def register(request: Request, user: User):
    """регистрация"""
    try:
        userindb = UserInDB(
            username=user.username,
            hashed_password=pwd_context.hash(user.password),
            roles=["guest"],
        )
        cur_db = open_db(DB)
        if userindb.username in tuple(map(lambda x: x["username"], cur_db.values())):
            raise HTTPException(status_code=409, detail="User already exists")
        cur_db[str(uuid4())] = userindb.model_dump()
        save_to_db(DB, cur_db)
        return {"success": f"{user.username} is registered"}
    except Exception as e:
        return {"reg_eroor": e}


@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, response: Response, user: User = Depends(auth_user)):
    """логин и получение токенов. Установка access токена в куки"""
    access_token = create_jwt_token({"sub": user.username}, type="ACCESS")
    refresh_token = create_jwt_token({"sub": user.username}, type="REFRESH")
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        httponly=True,
    )
    return {"access_token": f"Bearer {access_token}", "refresh_token": refresh_token}


@app.get("/protected_resource")
@PermissionChecker(["admin"])
@limiter.limit(get_rate_limit_by_role)
async def protected_resource(
    request: Request, username: str = Depends(decode_jwt_method)
):
    """защищенный конечный путь"""

    return {"success": f"secret information for {username}"}


# объектно-ориентированный контроль доступа
# ______________________________________________________________________________________
@app.get("/protected_resource/{user_name}")
@PermissionChecker(["admin", "user", "guest"])
@limiter.limit(get_rate_limit_by_role)
@OwnershipCheck()
async def get_info(
    request: Request, user_name: str, username: str = Depends(decode_jwt_method)
):
    return get_resource(user_name)


@app.post("/protected_resource/{user_name}")
@PermissionChecker(["admin", "user"])
@limiter.limit(get_rate_limit_by_role)
@OwnershipCheck()
async def post_info(
    request: Request,
    user_name: str,
    resourse_info: Optional[Resourse_info] = None,
    username: str = Depends(decode_jwt_method),
):
    if resourse_info is None:
        raise HTTPException(status_code=422, detail="Нет информации")

    return {"api_method": "post", "success": create_resource(user_name, resourse_info)}


@app.put("/protected_resource/{user_name}")
@PermissionChecker(["admin", "user"])
@limiter.limit(get_rate_limit_by_role)
@OwnershipCheck()
async def put_info(
    request: Request,
    content_to_put: Resourse_info,
    user_name: str,
    username: str = Depends(decode_jwt_method),
):
    return put_info_to_resource(user_name, content_to_put)


@app.delete("/protected_resource/{user_name}")
@PermissionChecker(["admin", "user"])
@limiter.limit(get_rate_limit_by_role)
@OwnershipCheck()
async def delete_info(
    request: Request, user_name: str, username: str = Depends(decode_jwt_method)
):
    return delete_resource(user_name)


# обновление JWT токена
# ______________________________________________________________________________________


@app.post("/refresh")
@limiter.limit("5/minute")
async def validate_refresh(
    request: Request, response: Response, refresh_token: RefreshToken
):
    """обнолвение токенов по refresh токену"""
    return validate_refresh_token(refresh_token.refresh_token, response)


# Роли
# ______________________________________________________________________________________


@app.post("/set_roles")
@PermissionChecker(["admin"])
@limiter.limit(get_rate_limit_by_role)
async def set_roles(
    request: Request,
    user_to_set: UserToSetRoles,
    username: str = Depends(decode_jwt_method),
):
    change_role(user_to_set.username, user_to_set.roles)
    return {
        "success": f"{user_to_set.username} roles is changed to {user_to_set.roles}"
    }


@app.get("/admin")
@PermissionChecker(["admin"])
@limiter.limit(get_rate_limit_by_role)
async def admin_page(request: Request, username: str = Depends(decode_jwt_method)):
    """админская конечная точка"""
    return {"admin success": username}


@app.get("/user")
@PermissionChecker(["user"])
@limiter.limit(get_rate_limit_by_role)
async def guest_page(request: Request, username: str = Depends(decode_jwt_method)):
    """юзерская конечная точка"""
    return {"user success": username}


@app.get("/guest")
@PermissionChecker(["guest"])
@limiter.limit(get_rate_limit_by_role)
async def guest_page(request: Request, username: str = Depends(decode_jwt_method)):
    """гостевая конечная точка"""
    return {"guest success": username}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
