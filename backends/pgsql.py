#!/usr/bin/env python


import psycopg2
import sys
from backends import Backend

class PostgreSQL(Backend):
    __db = None
    __config = None

    def __connect(self, config):
        """
        Connects to Database
        :param config: parsed configuration file
        :return: database object
        """

        dbconn = None

        if "pgsql" in self.__config:
            host = None
            if "host" in self.__config["pgsql"]:
                host = self.__config["pgsql"]["host"]

            port = None
            if "port" in self.__config["pgsql"]:
                port = self.__config["pgsql"]["port"]

            user = None
            if "user" in self.__config["pgsql"]:
                user = self.__config["pgsql"]["user"]

            passphrase = None
            if "passphrase" in self.__config["pgsql"]:
                passphrase = self.__config["pgsql"]["passphrase"]

            database = None
            if "database" in self.__config["pgsql"]:
                database = self.__config["pgsql"]["database"]

            try:
                dbconn = psycopg2.connect(database=database, user=user, password=passphrase, host=host, port=port)
            except psycopg2.DatabaseError as error:
                sys.stderr.write("Error: Can't connect to database: %s\n" % (error.message))
                return None
        return dbconn

    def __init__(self, config):
        super(PostgreSQL, self).__init__(config)
        self.__config = config
        self.__db = self.__connect(config)

    def __del__(self):
        super(PostgreSQL, self).__del__()
        if self.__db:
            self.__db.close()

    def get_new_serial_number(self, cert):
        if "serial_number" in self.__config["global"]:
            if self.__config["global"]["serial_number"] == "random":
                pass