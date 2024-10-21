from fastapi import FastAPI, Depends
from pydantic import BaseModel
from typing import Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from datetime import timedelta, datetime
from config import secret_key, algorithm, access_token_exp_minutes

app = FastAPI(docs_url="/")

fake_db = {
    "johndoe": {
        "username": "johndoe",
        "password": "123"
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str


class User(BaseModel):
    username: Optional[str] = None
    password: str


def verify_password(password, hashed_password):
    return password == hashed_password


oauth_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_user(db: dict, username: str):
    if username in db:
        user_dict = db[username]
        return User(**user_dict)


def create_access_token(data: dict, expire_date: Optional[timedelta] = None):
    # Копируем информацию
    to_encode = data.copy()
    # Если передаем время действия токена доступа то создаем переменную с ним,
    # если нет, то сами указываем
    if expire_date:
        expire = datetime.utcnow() + expire_date
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    # Обновляем наш словарь и добавляем туда время
    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)

    return encoded_jwt


def authenticate_user(db: dict, username: str, password: str):
    user = get_user(db, username)
    if user:
        return user
    if not verify_password(password, user.password):
        return False
    return False


from fastapi import HTTPException


@app.post("/token", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_db, form.username, form.password)
    if not user:
        return HTTPException(status_code=404,
                             detail="Неправильный пароль или username")
    access_token_expire = timedelta(minutes=access_token_exp_minutes)
    access_token = create_access_token(data={"sub": user.username},
                                       expire_date=access_token_expire)
    return {"access_token": access_token,
            "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth_scheme)):
    exception = HTTPException(status_code=404,
                              detail="Неправильный токен")
    try:
        payload = jwt.decode(token, secret_key, algorithms=algorithm)
        username = payload.get("sub")
        if username is None:
            raise exception
        token_data = TokenData(username=username)
    except jwt.JWTError:
        raise exception
    user = get_user(fake_db, token_data.username)
    if user is None:
        raise exception
    return user


# Получаем пользователя который автаризован на данный момент
@app.get("/user/me", response_model=User)
async def user_me(user: User = Depends(get_current_user)):
    return user


