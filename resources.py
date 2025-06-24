from functools import wraps
from fastapi import HTTPException

# files
from db import open_db, save_to_db, get_user_from_db, get_resource_info
from settings import DB_resources
from models import Resourse_info




class OwnershipCheck:
    """Проверка принадлежности ресурса пользователю. Админам можно все"""

    def __call__(self, func):

        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                http_method = kwargs.get("request").method
                # хозяин ресурса
                resource_owner = kwargs.get("user_name")
                # данные ресурса
                # тот кто открыл ссылку
                current_user = get_user_from_db(kwargs.get("username"))  # Pydantic
                # админам можно все
            except Exception as e:
                raise HTTPException(
                    status_code=409,
                    detail="Ошибка получения resource_owner или current_user",
                )
            if "admin" in current_user.roles:
                return await func(*args, **kwargs)
                # роли

            if http_method == "GET" and get_resource_info(resource_owner).is_public:
                return await func(*args, **kwargs)
            if resource_owner == current_user.username:
                return await func(*args, **kwargs)
            raise HTTPException(status_code=403, detail=f"В доступе отказано")

        return wrapper


# GET
# просто получение инфы
def get_resource(user_name):
    """"""
    return get_resource_info(user_name).model_dump()


# POST
# создание данных для чела. Если данный чел есть в ресурсах, вызвать ошибку
def create_resource(user_name: str, data: Resourse_info):
    cur_db = open_db(DB_resources)
    if user_name in cur_db:
        raise HTTPException(status_code=409, detail="Resource already exist")
    try:
        cur_db[user_name] = data.model_dump()
        save_to_db(DB_resources, cur_db)
    except:
        raise HTTPException(status_code=404, detail="Ошибка в создании ресурса")

    return {"success": f"profile with data {data} is created"}


# PUT
# проверка наличия чела в ресурсах и если он есть, то обновить его данные
def put_info_to_resource(user_name, content_to_put: Resourse_info):
    cur_db = open_db(DB_resources)
    new_content = cur_db[user_name].get("content", "") + content_to_put.content
    cur_db[user_name] = {"content": new_content, "is_public": content_to_put.is_public}
    save_to_db(DB_resources, cur_db)
    return {"success": new_content}


# DELETE
# удаление данных
def delete_resource(user_name):
    try:
        cur_db = open_db(DB_resources)
        cur_db.pop(user_name)
        save_to_db(DB_resources, cur_db)
        return {"success": f"Данные {user_name} удалены."}
    except KeyError:
        return {"error": f"resurce doesnt exist (Nothing to delete)"}
