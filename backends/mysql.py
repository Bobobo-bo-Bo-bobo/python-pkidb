#!/usr/bin/env python


import base64
import hashlib
import logging
import logging.handlers
import os
import MySQLdb
import random
import sys
import time
import OpenSSL
from backends import Backend

class MySQL(Backend):
    __db = None
    __config = None
    __logger = None

    def __connect(self, config):
        """
        Connects to Database
        :param config: parsed configuration file
        :return: database object
        """

        dbconn = None

        if "mysql" in self.__config:
            host = None
            if "host" in self.__config["mysql"]:
                host = self.__config["mysql"]["host"]

            port = None
            if "port" in self.__config["mysql"]:
                port = self.__config["mysql"]["port"]

            user = None
            if "user" in self.__config["mysql"]:
                user = self.__config["mysql"]["user"]

            passphrase = None
            if "passphrase" in self.__config["mysql"]:
                passphrase = self.__config["mysql"]["passphrase"]

            database = None
            if "database" in self.__config["mysql"]:
                database = self.__config["mysql"]["database"]

            try:
                dbconn = MySQLdb.connect(db=database, user=user, passwd=passphrase, host=host, port=port)
            except MySQLdb.Error as error:
                self.__logger.error("Can't connect to database: %s\n" % (error.message,))
                sys.stderr.write("Error: Can't connect to database: %s\n" % (error.message,))
                return None
        return dbconn

    def __init_logger(self):
        # setup logging first
        self.__logger = logging.getLogger(__name__)
        self.__logger.setLevel(logging.INFO)

        address = '/dev/log'
        handler = logging.handlers.SysLogHandler(address=address)
        handler.setLevel(logging.INFO)
        name = os.path.basename(sys.argv[0])
        format = logging.Formatter(name + " %(name)s:%(funcName)s:%(lineno)d %(levelname)s: %(message)s")
        handler.setFormatter(format)

        self.__logger.addHandler(handler)

    def __init__(self, config):
        super(MySQL, self).__init__(config)

        self.__init_logger()
        self.__config = config
        self.__db = self.__connect(config)
        if not self.__db:
            self.__logger.error("Unable to connect to database")
            sys.exit(4)

    def __del__(self):
        super(MySQL, self).__del__()
        if self.__db:
            self.__logger.info("Disconnecting from database")
            self.__db.close()

    def _has_serial_number(self, serial):
        pass

    def _get_last_serial_number(self):
        pass

    def _get_new_serial_number(self, cert):
        pass

    def _store_extension(self, extlist):
        pass

    def _store_signature_algorithm(self, cert):
        pass

    def _store_request(self, csr):
        pass

    def store_certificate(self, cert, csr=None, revoked=None, replace=False, autorenew=None, validity_period=None):
        pass

    def housekeeping(self, autorenew=True, validity_period=None, cakey=None):
        pass

    def get_statistics(self):
        pass

    def _insert_empty_cert_data(self, serial, subject):
        pass

    def _get_digest(self):
        pass

    def remove_certificate(self, serial):
        pass

    def generate_revocation_list(self):
        pass

        pass

    def revoke_certificate(self, serial, reason, revocation_date):
        pass

    def get_certificate(self, serial):
        pass

    def _get_state(self, serial):
        pass

    def dump_database(self):
        pass

    def list_serial_number_by_state(self, state):
        pass

    def restore_database(self, dump):
        pass

