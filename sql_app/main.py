from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import schema
from sqlalchemy.orm import Session

from . import crud, models, schemas
from .database import SessionLocal, engine

# pythonだとAlembicというmigrationツールがあるらしい
# ここでは、シンプルに作るだけ
models.Base.metadata.create_all(bind=engine)

app = FastAPI()


# Dependency: FastAPIでは、Dependencyを定義することで、実行時に対象のオブジェクトをDIできる
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400,
                            detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.get("/users", response_model=list[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.post("/users/{user_id}/items/", response_model=schemas.Item)
def create_item_for_user(
        user_id: int, item: schemas.ItemCreate, db: Session = Depends(get_db)):
    return crud.create_user_item(db=db, item=item, user_id=user_id)


@app.get("/items/", response_model=list[schemas.Item])
def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    # todo: この場合に、OpenAPIのドキュメントがどうなってるか確認する
    items = crud.get_items(db, skip=skip, limit=limit)
    return items
