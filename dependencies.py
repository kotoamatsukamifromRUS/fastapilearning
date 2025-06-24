from fastapi import HTTPException, Request
from functools import wraps
from contextvars import ContextVar

# files
from settings import DB
from db import get_user_from_db, open_db, save_to_db
from security import decode_jwt


def change_role(username: str, roles: list):
    """меняет роль любого юзера"""
    try:
        cur_db = open_db(DB)
        for user_id, user_data in cur_db.items():
            if user_data["username"] == username:
                cur_db[user_id]["roles"] = roles
        save_to_db(DB, cur_db)
        return {"success": "поменял роль"}
    except Exception as e:
        raise HTTPException(
            status_code=404, detail="Не получилось поменять роль. Сорян :("
        )


#
def know_the_args(func):
    """декоратор для получения аргументов"""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        print(f"Аргументы функции {func.__name__}: args={args}, kwargs={kwargs}")
        return await func(*args, **kwargs)

    return wrapper


# создание переменной для хранения контекста
request_ctx_var: ContextVar[Request | None] = ContextVar(
    "request_ctx_var", default=None
)


def get_rate_limit_by_role() -> str:
    """Получение лимита количества запросов по роли"""
    try:
        request = request_ctx_var.get()
        assert request
        authorization = request.cookies.get("access_token")
        assert authorization
        scheme, _, token = authorization.partition(" ")
        username = decode_jwt(authorization)["sub"]
        user_roles = get_user_from_db(username).roles
        if "admin" in user_roles:
            return "1000/minute"
        elif "user" in user_roles:
            return "50/minute"
        return "20/minute"
    # при ошибке миниум возмлжностей
    except Exception as e:
        print(f"Ошибка получения лимита по времени,{e}")
        return "20/minute"


def get_ownership_by_role():
    pass
