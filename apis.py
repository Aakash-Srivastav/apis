from os import curdir
from sqlite3 import Cursor
from tkinter.tix import Select
from passlib.context import CryptContext
from fastapi import FastAPI , HTTPException , Depends ,status
import databases , sqlalchemy , datetime , uuid
from pydantic import BaseModel , Field
from typing import List,Union
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import psycopg2
import pandas as pd

pwd_context = CryptContext(schemes=["bcrypt"], deprecated ="auto")



#oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

##Postgres Database
DATABASE_URL = "postgresql://postgres:123456@127.0.0.1:5432/dbtest2"
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "py_users",
    metadata,
    sqlalchemy.Column("id" , sqlalchemy.String , primary_key = True),
    sqlalchemy.Column("username" , sqlalchemy.String),
    sqlalchemy.Column("password" , sqlalchemy.String ),
    sqlalchemy.Column("create_at" , sqlalchemy.String ),
)

engine = sqlalchemy.create_engine(
    DATABASE_URL
)
metadata.create_all(engine)

#def fake_hash_password(password: str):
#    return "fakehashed" + password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

##Models
class UserList(BaseModel):
    id :str
    username : str
    password : str
    create_at :str
    disabled: Union[bool, None] = None

#class UserInDB(UserList):
#    hashed_password: str

class UserEntry(BaseModel):
    username :str
    password :str

class UserUpdate(BaseModel):
    id : str
    password : str

class UserDelete(BaseModel):
    username : str
    password : str



def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return user_dict

def fake_decode_token(token):

    df = pd.read_sql("select * from \"py_users\"",engine)
    data_df = df.set_index(['username'],drop=False)
    data = data_df.to_dict(orient='index')

    user = get_user(data, token)
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

#async def get_current_active_user(current_user: UserList = Depends(get_current_user)):
#    if current_user.disabled:
#        raise HTTPException(status_code=400, detail="Inactive user")
#    return current_user

app = FastAPI()

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):

    df = pd.read_sql("select * from \"py_users\"",engine)
    username_list = df["username"].values.tolist()
    pass_list = df["password"].values.tolist()

    if form_data.username in username_list:
        a = username_list.index(form_data.username)

    if form_data.username not in username_list:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if not form_data.password == pass_list[a]:
        raise HTTPException(status_code=400, detail="Incorrect password")

    return {"access_token": form_data.username, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: UserList = Depends(get_current_user)):
    return current_user


@app.get("/users",response_model=List[UserList])
async def find_all_users():
    query = users.select()
    return await database.fetch_all(query)

@app.post("/users",response_model=UserList)
async def register_user(user:UserEntry):
    df = pd.read_sql("select * from \"py_users\"",engine)
    username_list = df["username"].values.tolist()

    if "@gmail.com" not in user.username:
        raise HTTPException(status_code=400,detail="Invalid ID")
    elif user.username in username_list:
       raise HTTPException(status_code=400,detail="username already registered")
    else:
        gID = str(uuid.uuid1())
        gDate = str(datetime.datetime.now())
        query = users.insert().values(
            id = gID,
            username = user.username,
            password = pwd_context.hash(user.password),
            create_at = gDate
        )
        await database.execute(query)
        return{
            "id" : gID,
            **user.dict(),
            "create_at" : gDate
        }

@app.get("/users/{userId}",response_model=UserList)
async def find_user_by_id(username : str):
    query = users.select().where(users.c.username == username)
    return await database.fetch_one(query)

#@app.put("/users" , response_model=UserList)
#async def update_user(user:UserUpdate):
#    gDate = str(datetime.datetime.now())
#    query = users.update().\
#        where(users.c.id == user.id).\
#        values(
#            password = user.password,
#            create_at = gDate
#        )
#    await database.execute(query)
#    return await find_user_by_id(user.id)

@app.delete("/users{userId}")
async def delete_user(user:UserDelete):

    df = pd.read_sql("select * from \"py_users\"",engine)
    username_list = df["username"].values.tolist()
    pass_list = df["password"].values.tolist()

    if user.username in username_list:
        a = username_list.index(user.username)

    if user.username not in username_list:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    if not user.password == pass_list[a]:
        raise HTTPException(status_code=400, detail="Incorrect password")

    query = users.delete().where(users.c.username == user.username)
    await database.execute(query)

    return{
        "message" : "This user has successfully deleted"
    }

