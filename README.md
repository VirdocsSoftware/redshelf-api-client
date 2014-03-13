redshelf-api-client
===================

The RedShelf Python client is a reference client for building network requests to the API.

Requirements
------------
The client library requires the following libraries:

* [requests](http://docs.python-requests.org/en/latest/)
* [pycrypto](https://pypi.python.org/pypi/pycrypto)

sudo pip install requests

sudo pip install pycrypto

Installation
------------
Clone the client library from github for installation:

git clone https://github.com/VirdocsSoftware/redshelf-api-client.git

Basic Usage
------------
Import and instance the client object:

    from client import ClientV1
    c = ClientV1()
    c.set_user('0d72df20f23558620646fb3ea030f5')
    c.load_key('/path/to/private/key.key')

API Documentation
------------
See [http://api.redshelf.com/docs/](http://api.redshelf.com/docs/) for details.