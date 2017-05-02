from sqlalchemy import *
from sqlalchemy import create_engine, ForeignKey
from sqlalchemy import Column, Date, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask import session
from flask_login import (LoginManager, login_required, login_user,
                         current_user, logout_user, UserMixin)
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

engine = create_engine('sqlite:///tutorial.db', echo=True)
Base = declarative_base()

########################################################################
class User(Base, UserMixin):
    """"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    pw_hash = Column(String)
    authenticated = Column(Boolean)
    email = Column(String)
    admin = Column(Boolean)
    role = Column(String)

    #----------------------------------------------------------------------
    @staticmethod
    def get(userid):
        Session = sessionmaker(bind=engine)
        s = Session()
        query = s.query(User).filter(User.id == userid)
        result = query.first()

        if result:
            return result
        return None

    @staticmethod
    def all():
        Session = sessionmaker(bind=engine)
        s = Session()
        query = s.query(User).all()
        if query:
            return query
        return None

    @staticmethod
    def delete(username):
        Session = sessionmaker(bind=engine)
        s = Session()
        query = s.query(User).filter(User.username == username)
        result = query.first()
        s.delete(result)
        s.commit()

    @staticmethod
    def get_by_username(username):
        Session = sessionmaker(bind=engine)
        s = Session()
        query = s.query(User).filter(User.username == username)
        result = query.first()
        if result:
            return result
        return None

    def generate_auth_token(self, expiration = 300):
        s = Serializer("KEYYYYY", expiration)
        return s.dumps({ 'id': self.id })

    @staticmethod
    def verify_auth_token(token):
        s = Serializer("KEYYYYY")
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None # valid token, but expired
        except BadSignature:
            return None # invalid token
        user = User.get(data['id'])
        if user is not None:
            return user
        else:
            return None

    def __init__(self, username, password, email, admin, role):
        self.username = username
        self.set_password(password)
        self.authenticated = False
        self.set_email(email)
        self.admin = admin
        self.role = role

    def set_password(self, password):
        self.pw_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.pw_hash, password)

    def is_active(self):
        return True

    def get_id(self):
        return self.id

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return False

    def get_email(self):
        return self.email

    def set_email(self, email):
        self.email = email

    def is_admin(self):
        return self.admin


# create tables
Base.metadata.create_all(engine)
