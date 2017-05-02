import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tabledef import *

engine = create_engine('sqlite:///tutorial.db', echo=True)

# create a Session
Session = sessionmaker(bind=engine)
session = Session()

user = User("admin","admin","admin@example.com", True, "admin")
session.add(user)

user = User("test","password","test@example.com", False, "user")
session.add(user)

user = User("zhou","password","zhou@example.com", False, "user")
session.add(user)

# commit the record the database
session.commit()

session.commit()
