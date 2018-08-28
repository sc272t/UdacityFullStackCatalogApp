from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

session.query(User).delete()
session.query(Category).delete()
session.query(Item).delete()

# Create dummy user
user1 = User(name="Jit Chakraborty", email="soumyarock@gmail.com",
             picture='')
user2 = User(id = 2, name="sc299", email="sc299@njit.edu", picture="")
session.add(user1)
session.add(user2)
session.commit()

# Add category values in table = category

categoryArray = ['Full Stack Web Developer','Data Analyst','Android Developer','Front End Web Developer','Machine Learning','IOS Developer','Big Data Analyst','Business Analyst','Drools Developer','Enterprise Architect']

for category in categoryArray:
    category = Category(user_id=1, name=category)
    session.add(category)
    session.commit()


# Add items for each category
    
# items for category_id 1
item1 = Item(user_id=1, name="Python", description="Python is a programming language", category_id=1)
item2 = Item(user_id=1, name="Html", description="Hyper text mark up language", category_id=1)
item3 = Item(user_id=1, name="Css", description="Cascaded Style Sheet", category_id=1)

session.add(item1)
session.add(item2)
session.add(item3)

session.commit()

# items for category_id 2

item1 = Item(user_id=1, name="Statistics", description="Statistics", category_id=2)
item2 = Item(user_id=1, name="Python", description="Python is a programming language", category_id=2)
item3 = Item(user_id=1, name="R", description="R is a programming language and free software environment for statistical computing and graphics", category_id=2)

session.add(item1)
session.add(item2)
session.add(item3)

session.commit()

# items for category_id 3

item1 = Item(user_id=1, name="Java", description="Java is a programming language", category_id=3)
item2 = Item(user_id=1, name="Android", description="Android is an operating system", category_id=3)

session.add(item1)
session.add(item2)

session.commit()

print "Added categories and items!\n"

# select * from user table

print "Added users!"

result1 = engine.execute('SELECT * FROM '
                        '"user"')
for r in result1:
   print(r)


# select * from category table
print "\nAdded categories!"
result2 = engine.execute('SELECT * FROM '
                        '"category"')
for r in result2:
   print(r)

# select * from item table

print "\nAdded items!"

result3 = engine.execute('SELECT * FROM '
                        '"item"')
for r in result3:
   print(r)
