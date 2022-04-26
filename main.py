import imp
from fastapi import Depends, FastAPI,Path,Query,Body,HTTPException
from models import User
from mongoengine import connect
import json
from pydantic import BaseModel
from passlib.context import CryptContext
from datetime import timedelta,datetime
from jose import jwt
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm

app=FastAPI()
connect(db="dbtest",host="localhost",port=27017)




@app.get("/users")
def home():
    users=User.objects().to_json()
    users_list=json.loads(users)
    return {"users":users_list}


@app.get("/user/{user_id}")
def get_user(user_id):
    user=User.objects().get(user_id=user_id)
    user_dict={
        "user_id":user.user_id,
        "name":user.name,
        "username":user.username,

    }
    return user_dict


@app.get("/searchuser")
def get_user(name):
    users=json.loads(User.objects.filter(name=name).to_json())
    return {"users":users}

class NewUser(BaseModel):
    user_id:int
    name:str
    username:str
    password:str


@app.post("/add_user")
def add_user(user:NewUser):
    new_user=User(user_id=user.user_id,
                 name=user.name,
                 username=user.username,
                 password=user.password,
                 )
    new_user.save()

    return {"message":"user add"}             

class UserRegister(BaseModel):
    username:str
    password:str

pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

@app.post("/signup")
def signup(new_user:UserRegister):
    user=User(username=new_user.username,
            password=get_password_hash(new_user.password))
    user.save()        

    return {"message":"new user created"} 


oauth2_schema=OAuth2PasswordBearer(tokenUrl="token")

def authenticate_user(username,password):
    try:
        user=json.loads(User.objects.get(username=username).to_json())
        
        password_check=pwd_context.verify(password,user['password'])
        return password_check
    except User.DoesNotExist:
        return False  

SECRET_KEY="788161854d31b1ffd5e36c3b35dd2ed5d155c98e370ca3034377d5e912842ca9"          
ALGORITHEM="HS256"
def create_access_token(data:dict,expire_delta:timedelta):
    to_encode=data.copy()

    expire = datetime.utcnow() + expire_delta
    to_encode.update({"exp":expire})

    encode_jwt=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHEM)

    return encode_jwt

@app.post("/token")
def login(form_data:OAuth2PasswordRequestForm=Depends()):
    username=form_data.username
    password=form_data.password

    if authenticate_user(username,password):
        access_token=create_access_token(data={"sub":username},expire_delta=timedelta(minutes=30))
        return {"access_token":access_token,"token_type":"bearer"}
    else:
        raise HTTPException(status_code=400,detail="incorrect username or password")    

@app.get("/")
def home(token:str=Depends(oauth2_schema)):
    return {"token":token}