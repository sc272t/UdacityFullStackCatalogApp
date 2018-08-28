#!/usr/bin/env python
from flask import Flask, render_template, request, redirect, jsonify, \
    url_for, flash
from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "MenuApp"

# Connect to Database and create database session

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# JSON API to download catalog categories and items
@app.route('/catalog/JSON')
def catalogJSON():
    """Generates JSON of all categories and related items item in catalog"""
    categoryList = session.query(Category).all()
    Categories = []
    for c in categoryList:
        category = c.serialize
        Categories.append(category)
        itemList = \
            session.query(Item).filter_by(category_id=c.id).order_by(Item.id)
        Items = []
        for item in itemList:
            Items.append(item.serialize)
        category['Items'] = Items
    return jsonify(Categories=Categories)


# JSON API to download selected item on catalog app
@app.route('/catalog/<categoryId>/<itemName>/JSON')
def itemJSON(categoryId, itemName):
    """Generates JSON of selected item in catalog"""
    SelectedItem = session.query(Item).filter_by(name=itemName,
                                                 category_id=categoryId).one()
    return jsonify(Item=SelectedItem.serialize)


# Home page for Catalog to display all categories and latest items
@app.route('/')
@app.route('/catalog')
def showCatalog():
    """Returns all categories and latest items in catalog"""
    categories = session.query(Category).order_by(asc(Category.id))
    # latest items
    items = session.query(Item).order_by(desc(Item.id))

    # create categories id-name mapping
    categoryList = {}
    for c in categories:
        categoryList[c.id] = c.name
    if 'username' not in login_session:
        return render_template('catalog.html', categories=categories,
                               items=items, categoryList=categoryList)
    else:
        return render_template('catalog.html', categories=categories,
                               items=items, categoryList=categoryList)


# get all items for a category
@app.route('/catalog/<categoryId>/items/')
def getItems(categoryId):
    """Returns all items for a selected category"""
    categories = session.query(Category).order_by(Category.id)
    category = session.query(Category).filter_by(id=categoryId).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    creator = getUserInfo(category.user_id)

    if 'username' not in login_session or\
       creator.id != login_session['user_id']:
        return render_template('items.html', items=items,
                               category=category, categories=categories)
    else:
        return render_template('items.html', items=items,
                               category=category, categories=categories)


# get item by itemName for a category
@app.route('/catalog/<categoryId>/<itemName>/')
def getItem(itemName, categoryId):
    """Return details of a selected Item"""
    category = session.query(Category).filter_by(id=categoryId).one()
    categories = session.query(Category).order_by(Category.id)

    item = session.query(Item).filter_by(name=itemName,
                                         category_id=category.id).one()
    creator = getUserInfo(item.user_id)
    return render_template('item_show.html', item=item,
                           category=category,
                           creator=creator, categories=categories)


# Add an item to a selected category
@app.route('/catalog/<categoryId>/new', methods=['GET', 'POST'])
def addItem(categoryId):
    """Method to Add item to a category"""
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(id=categoryId).one()
    if login_session['user_id'] != category.user_id:
        flash('You are not authorized to add item to this category!')
        return redirect('/')
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=category.id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % (newItem.name))
        return redirect(url_for('showCatalog'))
    else:
        return render_template('item_new.html', categoryId=categoryId)


# Add new item from home page by selecting category from dropdown
@app.route('/catalog/new', methods=['GET', 'POST'])
def newItem():
    """Add new item from home page by selecting category from dropdown"""
    if 'username' not in login_session:
        return redirect('/login')
    elif request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       category_id=request.form['category_id'],
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % (newItem.name))
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).order_by(Category.name)
        return render_template('item_new2.html', categories=categories)


# Create a new Category
@app.route('/catalog/newCategory/', methods=['GET', 'POST'])
def addCategory():
    """Add New Category to catalog"""
    if 'username' not in login_session:
        return redirect('/login')
    # Addition of new Category restricted to admin only
    if login_session['user_id'] != 1:
        flash('You are not authorized to add new categories.')
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).order_by(Category.name)
        return render_template('category_new.html', categories=categories)


# Edit Item
@app.route('/catalog/<categoryId>/<itemName>/edit', methods=['GET', 'POST'])
def editItem(itemName, categoryId):
    """Allows authorized users to Edit a selected item for a category"""
    if 'username' not in login_session:
        return redirect('/login')

    categories = session.query(Category).order_by(Category.name)
    category = session.query(Category).filter_by(id=categoryId).one()
    editedItem = session.query(Item).filter_by(name=itemName,
                                               category_id=category.id).one()

    if login_session['user_id'] != editedItem.user_id:
        flash('You are not authorized to edit this item!')
        return redirect(url_for('showCatalog'))
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']

        if request.form['category']:
            # to update the category of an existing item
            selectedCategory = request.form['category']
            getId = session.query(Category).\
                filter_by(name=selectedCategory).one()
            editedItem.category_id = getId.id

        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited %s' % editedItem.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('item_edit.html', categoryId=categoryId,
                               item=editedItem, category=category,
                               categories=categories)


# Delete an item
@app.route('/catalog/<categoryId>/<itemName>/delete', methods=['GET', 'POST'])
def deleteItem(itemName, categoryId):
    """Allows authorized user to delete an existing item"""
    if 'username' not in login_session:
        return redirect('/')

    categories = session.query(Category).order_by(Category.id)
    category = session.query(Category).filter_by(id=categoryId).one()
    itemToDelete = session.query(Item).filter_by(name=itemName,
                                                 category_id=category.id).one()
    if login_session['user_id'] != itemToDelete.user_id:
        flash('You are not authorized to delete this item!')
        return redirect('/')
    if request.method == 'POST':
        session.delete(itemToDelete)
        flash('Item Successfully Deleted')
        session.commit()
        return redirect('/')
    else:
        return render_template('item_delete.html', item=itemToDelete,
                               category=category, categoryId=categoryId,
                               categories=categories)


# Delete a category
@app.route('/catalog/<categoryId>/delete', methods=['GET', 'POST'])
def deleteCategory(categoryId):
    """Allows authorized user to delete an existing category and it's items"""
    if 'username' not in login_session:
        return redirect('/login')
    categoryToDelete = session.query(Category).filter_by(id=categoryId).one()
    # items = session.query(Item).filter_by(category_id=categoryId).all()
    if login_session['user_id'] != categoryToDelete.user_id:
        flash('You are not authorized to delete this Category!')
        return redirect('/')
    if request.method == 'POST':
        session.delete(categoryToDelete)
        # delete any existing items for categoryToDelete being deleted
        session.query(Item).filter_by(category_id=categoryToDelete.id).delete()
        flash('Category and related items are successfully Deleted')
        session.commit()
        return redirect('/')
    else:
        return render_template('category_delete.html',
                               category=categoryToDelete,
                               categoryId=categoryId)


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    """Function to login and authenticate to Catalog App"""
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """google plus signin and authentication method"""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']

    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')

    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += \
        ' " style = "width: 300px; height: 300px;\
    border-radius: 150px;-webkit-border-radius: 150px;\
    -moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Disconnect - Revoke a current user's token and reset login_session
@app.route('/gdisconnect')
def gdisconnect():
    """google plus logout method"""
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response
        (json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps
                                 ('Failed to revoke token for given user.',
                                  400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """method for facebook oauth autentication"""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps
                                 ('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data
    # print "access token received %s " % access_token

    app_id = json.loads(open('clientsecrets_facebook.json', 'r')
                        .read())['web']['app_id']
    app_secret = json.loads(open('clientsecrets_facebook.json', 'r'
                                 ).read())['web']['app_secret']
    url = \
        'https://graph.facebook.com/oauth/access_token?grant_type= \
    fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' \
        % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    # token to get user info from api
    token = result.split("&")[0]
    url = \
        'https://graph.facebook.com/v2.8/me?\
    fields=id%2Cname%2Cemail%2Cpicture&access_token=' \
        + access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data['id']

    # The token must be stored in login_session in order to properly disconnect
    login_session['access_token'] = access_token
    # check if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """method for facebook logout and delete user login session"""
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
        % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    """ Method to logout user from CatalogApp """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        # del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have been successfully logged out from Catalog App.")

        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    # facebook oauth redirect url requires https
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
    # app with only work with google plus sign in for http/localhost
    # app.run(host='0.0.0.0', port=8000)
