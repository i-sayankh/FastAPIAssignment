from mongoengine import Document, StringField
from .schemas import UserRole


class User(Document):
    username = StringField(required=True, unique=True)
    password = StringField(required=True)
    role = StringField(required=True, default=UserRole.USER.value)

    meta = {'collection': 'users'}
