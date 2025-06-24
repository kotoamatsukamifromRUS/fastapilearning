from pydantic import BaseModel, Field, field_validator
from typing import List, Optional


class RoleValidatorMixin(BaseModel):
    roles: List[str] = Field(..., description="List of roles: admin, user, guest")

    @field_validator("roles")
    def validate_roles(cls, roles):
        if not isinstance(roles, list):
            raise ValueError("Roles must be a list")

        valid_roles = {"admin", "user", "guest"}
        invalid_roles = set(roles) - valid_roles

        if invalid_roles:
            raise ValueError(
                f"Invalid roles: {invalid_roles}. Valid roles are: {valid_roles}"
            )
        return roles


class UserBase(BaseModel):
    username: str = Field(min_length=1)


class User(UserBase):
    password: str = Field(min_length=8)


class UserInDB(UserBase, RoleValidatorMixin):
    hashed_password: str = Field(min_length=1)


class UserToSetRoles(UserBase, RoleValidatorMixin):
    pass


class RefreshToken(BaseModel):
    refresh_token: str


class Resourse_info(BaseModel):
    content: str = ""
    is_public: Optional[bool] = False
