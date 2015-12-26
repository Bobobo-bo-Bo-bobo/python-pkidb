#!/usr/bin/env python
from distutils.core import setup


PKIDB_SETUP = {
    'name' : 'pkidb',
    'version' : '0.8.0',
    'description' : 'PKI system based on a SQL database',
    'long_description' : 'PKI system based on a SQL database',
    'author_email' : 'ecbeb08bb9f1b8e8f421fbf4c28e3033ecb13bc0@ypbind.de',
    'scripts' : ['bin/pkidb'],
    'packages' : ['pkidbbackends'],
    'package_data' : {'pkidbbackends' : ['pkidbbackends/*.py'], },
    'license' : open('LICENSE').read()
}

setup(**PKIDB_SETUP)
