from mongoengine import Document
from mongoengine.fields import StringField,IntField

class User(Document):
    user_id=IntField()
    name=StringField()
    username=StringField()
    password=StringField()