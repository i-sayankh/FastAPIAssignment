from mongoengine import Document, StringField, DateTimeField
from datetime import datetime


class Project(Document):
    name = StringField(required=True)
    description = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    created_by = StringField(required=True)

    meta = {'collection': 'projects'}
