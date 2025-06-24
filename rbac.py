from fastapi import HTTPException, status
from functools import wraps
from db import get_user_from_db


class PermissionChecker:
    """Декоратор проверки ролей"""

    def __init__(self, roles: list[str]):
        self.roles = roles  # Список разрешённых ролей из списка

    def __call__(self, func):

        @wraps(func)
        async def wrapper(*args, **kwargs):
            if "guest" in self.roles:
                return await func(*args, **kwargs)
            # получение ролей пользователя из db
            try:
                # username как в названии переменной. Напрмиер, username: dict = Depends(...)
                user = get_user_from_db(kwargs["username"])
                user_roles = user.roles
                if user_roles == []:
                    raise
            except Exception as e:
                raise HTTPException(
                    status_code=403, detail=f"Ошибка получения username,{e}"
                )
            # проверка
            if "admin" in user_roles or any(role in user_roles for role in self.roles):
                return await func(*args, **kwargs)
            raise HTTPException(status_code=403, detail="нет доступа")

        return wrapper
