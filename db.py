from fastapi.exceptions import HTTPException
import json
from secrets import compare_digest

# files
from models import UserInDB, Resourse_info
from settings import DB, DB_REFRESH_TOKENS, DB_resources


def open_db(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cur_json = json.load(f)
        return cur_json


def save_to_db(path, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# доработать идею юзать user_id
def get_user_from_db(username_to_check: str):
    cur_db = open_db(DB)
    for user_id, data in cur_db.items():
        if compare_digest(data["username"], username_to_check):
            return UserInDB(
                username=data["username"],
                hashed_password=data["hashed_password"],
                roles=data["roles"],
            )
    raise HTTPException(status_code=404, detail="User not found")


def save_refresh_token_to_db(data: dict, new_token):
    """Сохранение рефреш токена в db"""
    username = data["sub"]
    cur_db = open_db(DB_REFRESH_TOKENS)
    cur_db[username] = new_token
    save_to_db(DB_REFRESH_TOKENS, cur_db)


def get_resource_info(owner_name):
    """Возвращение в pydantic контента юзера из db"""
    cur_db = open_db(DB_resources)
    try:
        info = cur_db[owner_name]
        return Resourse_info(**info)
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Нет такого ресурса")
