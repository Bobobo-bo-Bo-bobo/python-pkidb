#!/usr/bin/env python

import base64
import hashlib
import logging
import logging.handlers
import os
import sqlite3
import random
import sys
import time
import OpenSSL
from backends import Backend

class SQLite(Backend):
    __db = None
    __config = None
    __logger = None

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

    def __connect(self, config):
        db = None
        try:
            db = sqlite3.connect(config["sqlite3"]["database"])
        except sqlite3.Error as error:
            self.__logger.error("Can't connect to database %s: %s" % (config["sqlite3"]["database"], error.message))
            sys.stderr.write("Error: Can't connect to database %s: %s" % (config["sqlite3"]["database"], error.message))
            return None
        return db

    def __init__(self, config):
        super(SQLite, self).__init__(config)

        self.__init_logger()
        self.__config = config
        self.__db = self.__connect(config)
        if not self.__db:
            self.__logger.error("Unable to connect to database")
            sys.exit(4)

    def __del__(self):
        super(SQLite, self).__del__()
        if self.__db:
            self.__logger.info("Disconnecting from database")
            self.__db.close()

    def _get_state(self, serial):
        try:
            qdata = (serial, )

            cursor = self.__db.cursor()
            cursor.execute("SELECT state FROM certificate WHERE serial_number=?;", qdata)

            self.__logger.info("Getting state for certificate with serial number 0x%x" % (serial, ))

            result = cursor.fetchall()
            cursor.close()
            self.__db.commit()

            if len(result) > 0:
                self.__logger.info("Certificate with serial number 0x%x is %s" %
                                   (serial, self._certificate_status_reverse_map[result[0][0]]))

                return result[0][0]
            else:
                self.__logger.warning("No certificate with serial number 0x%x found in database" %
                                      (serial, ))
                return None
        except sqlite3.Error as error:
            sys.stderr.write("Error: Can't read certificate from database: %s\n" % (error.message, ))
            self.__logger.error("Can't read certificate from database: %s" % (error.message, ))
            return None


    def _has_serial_number(self, serial):
            query = (serial, )

        self.__logger.info("Looking for serial number 0x%x in database" % (serial, ))

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number FROM certificate WHERE serial_number=?;", query)
            result = cursor.fetchall()

            if len(result) == 0:
                self.__logger.info("Serial number 0x%x was not found in the database")
                return False
            else:
                self.__logger.info("Serial number 0x%x was found in the database")
                return True

        except sqlite3.Error as error:
            sys.stderr.write("Error: Can't query database for serial number: %s\n" % (error.message, ))
            self.__logger.error("Can't query database for serial number: %s" % (error.message, ))
            return None

    def _get_last_serial_number(self):
        serial = None

        self.__logger.info("Looking for last serial number")
        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number FROM certificate ORDER BY serial_number DESC LIMIT 1;")
            result = cursor.fetchall()
            if len(result) == 0:
                sys.stderr.write("Error: No serial number found in database\n")
                self.__logger.error("No serial number found in database")

            serial = result[0][0]

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            sys.stderr.write("Error: Can't lookup serial number from database: %s" % (error.message, ))
            self.__logger("Can't lookup serial number from database: %s" % (error.message, ))
            self.__db.rollback()
            return None

        self.__logger.info("Last serial number is 0x%x" % (serial, ))
        return result

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

    def revoke_certificate(self, serial, reason, revocation_date):
        pass

    def get_certificate(self, serial):
        pass

    def renew_certificate(self, serial, notBefore, notAfter, cakey):
        pass

    def dump_database(self):
        pass

    def list_serial_number_by_state(self, state):
        pass

    def restore_database(self, dump):
        pass

