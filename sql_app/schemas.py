from pydantic import BaseModel


# Pydanticのモデルは、
# - ベースとなる共通要素を持つクラス
# - 作成用のクラス
# - 読み込み・レスポンス用のクラス
# に分けて定義している。
# 特に、作成用のユーザクラスにだけ、パスワードを持っている。

class ItemBase(BaseModel):
    title: str
    description: str | None = None


class ItemCreate(ItemBase):
    pass


class Item(ItemBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int
    is_active: bool
    items: list[Item] = []

    class Config:
        orm_mode = True
