#!/usr/bin/env python
from distutils.core import setup


PKIDB_SETUP = {
    "name" : "pkidb",
    "version" : "0.8.4",
    "description" : "PKI system based on a SQL database",
    "long_description" : """PKI script for managing certificates.
Certificates are stored in a database.
Supported database backends are MySQL (via python-mysqldb), PostgreSQL (via python-psycopg2) and
SQLite3 (via python-pysqlite2)""",
    "author": "Andreas Maus",
    "author_email" : "python-pkidb@ypbind.de",
    "scripts" : ["bin/pkidb"],
    "packages" : ["pkidbbackends"],
    "package_data" : {"pkidbbackends" : ["pkidbbackends/*.py"], },
    "license" : open("LICENSE").read()
}

setup(**PKIDB_SETUP)
