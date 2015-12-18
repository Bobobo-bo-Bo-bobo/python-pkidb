#!/usr/bin/env python


import base64
import hashlib
import psycopg2
import sys
import time
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

    def _store_extension(self, extlist):
        result = []

        for extension in extlist:
            # primary key is the sha512 hash of name+critical+data
            pkey = hashlib.sha512(extension[0]+str(extension[1])+extension[2]).hexdigest()
            extdata = {
                "hash":pkey,
                "name":extension[0],
                "critical":str(extension[1]),
                "data":base64.b64encode(extension[2]),
            }

            try:
                cursor = self.__db.cursor()
                cursor.execute("LOCK TABLE extension;")
                cursor.execute("SELECT COUNT(hash) FROM extension WHERE hash='%s';" % (pkey, ))
                searchresult = cursor.fetchall()

                # no entry found, insert data
                if searchresult[0][0] == 0:
                    cursor.execute("INSERT INTO extension (hash, name, criticality, data) "
                                   "VALUES (%(hash)s, %(name)s, %(critical)s, %(data)s);", extdata)

                cursor.close()
                self.__db.commit()
                result.append(pkey)
            except psycopg2.Error as error:
                sys.stderr.write("Error: Can't look for extension in database: %s\n" % (error.pgerror, ))
                self.__db.rollback()
                return None
        return result

    def store_certificate(self, cert, csr=None, revoked=None):
        data = self._extract_data(cert, csr, revoked)

        # check if serial_number already exist
        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT COUNT(serial_number) FROM certificate WHERE serial_number=%(serial)s;", data)
            result = cursor.fetchall()
            cursor.close()
            self.__db.commit()
            if result[0][0] > 0:
                sys.stderr.write("Error: A certificate with serial number %s (0x%x) already exist\n" %
                                 (data["serial"], data["serial"]))
                return None

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't look up serial number: %s\n" % (error.pgerror, ))
            self.__db.rollback()

        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE certificate")
            cursor.execute("INSERT INTO certificate (serial_number, version, start_date, end_date, "
                           "subject, fingerprint_md5, fingerprint_sha1, certificate, state, issuer) VALUES "
                           "(%(serial)s, %(version)s, to_timestamp(%(start_date)s), "
                           "to_timestamp(%(end_date)s), %(subject)s, %(fp_md5)s, %(fp_sha1)s, "
                           "%(pubkey)s, %(state)s, %(issuer)s);", data)

            if "csr" in data:
                cursor.execute("UPDATE certificate SET signing_request=%(csr)s WHERE serial_number=%(serial)s;", data)

            if "revreason" in data:
                cursor.execute("UPDATE certificate SET revocation_reason=%(revreason)s, "
                               "revocation_date=to_timestamp(%(revtime)s), state=%(state)s WHERE "
                               "serial_number=%(serial)s;", data)

            if "extension" in data:
                extkeys = self._store_extension(data["extension"])
                if extkeys:
                    data["extkey"] = extkeys
                    cursor.execute("UPDATE certificate SET extension=%(extkey)s WHERE serial_number=%(serial)s;", data)
            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't update certificate data in database: %s\n" % (error.pgerror, ))
            self.__db.rollback()
            return None

    def validate_certficates(self):

        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE certificate;")

            qdata = {
                "valid":self._certificate_status_map["valid"],
                "invalid":self._certificate_status_map["invalid"],
                "expired":self._certificate_status_map["expired"],
                "now":time.time(),
            }

            # set all invalid certificates to valid if notBefore < now and notAfter > now
            cursor.execute("UPDATE certificate SET state=%(valid)s WHERE state=%(invalid)s AND "
                           "(start_date < to_timestamp(%(now)s)) AND (end_date > to_timestamp(%(now)s));", qdata)

            # set all valid certificates to invalid if notBefore >= now
            cursor.execute("UPDATE certificate SET state=%(invalid)s WHERE state=%(valid)s AND "
                           "(start_date >= to_timestamp(%(now)s));", qdata)

            # set all valid certificates to expired if notAfter <= now
            cursor.execute("UPDATE certificate SET state=%(expired)s WHERE state=%(valid)s AND "
                           "(end_date <= to_timestamp(%(now)s));", qdata)
            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't validate certificates: %s\n" % (error.pgerror, ))
            self.__db.rollback()
            return None

    def get_statistics(self):

        statistics = {}

        state_statistics = {}
        for state in self._certificate_status_map:
            state_statistics[state] = 0

        try:
            cursor = self.__db.cursor()

            cursor.execute("SELECT state, COUNT(state) FROM certificate GROUP BY state;")
            result = cursor.fetchall()

            for element in result:
                state_statistics[self._certificate_status_reverse_map[element[0]]] = element[1]

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't read certifcate informations from database:%s\n" % (error.pgerror, ))
            self.__db.rollback()
            return None
        statistics["state"] = state_statistics

        return statistics
