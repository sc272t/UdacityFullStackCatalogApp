### ProjectCatalogApp
The CatalogApp project consists of developing an application that provides a list of items within a variety of categories, 
as well as provide a user authentication system for CRUD functionality.
### CRUD
This app implements CRUD opreations from a database. Create, Update and Delete operations are only allowed for logged users.
This is a CatalogApp for maintaining Nanodegrees as Category and relevant courses/skills as Items.
The app allows authorized users to create a Category and create/edit/delete Items to a Category.

### APIs
This app implements a JSON endpoint that returns information of an item when clicked.
This app implements a JSON endpoint that serves all the categories and related items.

### Authentication & Authorization
This app uses Google and Facebook OAuth services for authentication.
Without authentication the app will only allow the user with default READ Only functionality. 

### Technologies Used
Python 2.7
HTML 5
Vagrant https://www.vagrantup.com/
VirtualBox https://www.virtualbox.org/

### How to run CatalogApp

1. Download the vagrant configuration https://github.com/udacity/fullstack-nanodegree-vm/blob/master/vagrant/Vagrantfile 
	OR 
	Clone the vm 'git clone [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm)'
2. 	Launch and login to the Vagrant VM

  ```
  cd vagrant
  vagrant up
  vagrant ssh
  ```
3.  Extract the ProjectCatalog.zip into the vagrant directory from local machine
 In the virtual machine go to the ProjectCatalog directory and execute the following steps:

  ```
  cd /vagrant/ProjectCatalog
  ```

4. Setup database and load initial data:

  ```
  python database_setup.py
  python load_data.py
  ```

5. Replace your client secrets for Facebook and Google sing in:

  * Replace your Google client secrets in `client_secrets.json`
  * Replace your Facebook client secrets in `clientsecrets_facebook.json`

  NOTE: You must configure your Google and Facebook apps correctly
  
  https://knowledge.udacity.com/questions/7842 to make app run on https
  Use the link and follow the instructions in it to generate self-signed certificate in order to run the app on https

6. Now you can run the application:

  ```
  python catalogApp.py
  ```

7. On a web browser enter `https://localhost:5000`
  NOTE: Facebook sign in only works with https
  Reference: https://knowledge.udacity.com/questions/7842 to make app run on https
  Use the link and follow the instructions in it to generate self-signed certificate in order to run the app on https
  If you intend to run using http and google signin please uncomment line 499 and comment out line 497 in catalogApp.py and use `http://localhost:5000` instead