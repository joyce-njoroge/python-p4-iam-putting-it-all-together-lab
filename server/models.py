from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import Column, String, Integer,ForeignKey
from sqlalchemy.orm import relationship, validates
from flask_bcrypt import generate_password_hash, check_password_hash

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    _password_hash = Column(String(128))
    image_url = Column(String(200))
    bio = Column(String(200))
    recipes = relationship('Recipe', backref='user', lazy=True)

    @hybrid_property
    def password_hash(self):
        raise AttributeError("password_hash is not accessible.")

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return check_password_hash(self._password_hash, password)

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username is required.")
        return username



class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    instructions = Column(String(500), nullable=False)
    minutes_to_complete = Column(Integer)
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError("Title is required.")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions:
            raise ValueError("Instructions are required.")
        if len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions
