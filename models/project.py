from mongoengine import Document, StringField, DateTimeField
from datetime import datetime
import uuid


class Project(Document):
    _id = StringField(required=True, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = StringField(required=True)
    description = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    created_by = StringField(required=True)


    meta = {'collection': 'projects'}
