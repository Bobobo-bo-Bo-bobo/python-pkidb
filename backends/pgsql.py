#!/usr/bin/env python


import base64
import hashlib
import psycopg2
import random
import sys
import time
import OpenSSL
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
            except psycopg2.Error as error:
                sys.stderr.write("Error: Can't connect to database: %s\n" % (error.message,))
                return None
        return dbconn

    def __init__(self, config):
        super(PostgreSQL, self).__init__(config)
        self.__config = config
        self.__db = self.__connect(config)
        if not self.__db:
            sys.exit(4)

    def __del__(self):
        super(PostgreSQL, self).__del__()
        if self.__db:
            self.__db.close()

    def _has_serial_number(self, serial):
        query = {
            "serial":serial,
        }

        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE certificate;")
            cursor.execute("SELECT serial_number FROM certificate WHERE serial_number=%(serial)s;", query)
            result = cursor.fetchall()

            if len(result) == 0:
                return False
            else:
                return True
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't query database for serial number: %s\n" % (error.pgerror, ))
            return None

        # Never reached
        return None

    def _get_last_serial_number(self):
        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number FROM certificate ORDER BY serial_number DESC LIMIT 1;")
            result = cursor.fetchall()
            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't lookup serial number from database: %s" % (error.pgerror, ))
            self.__db.rollback()
            return None

    def _get_new_serial_number(self, cert):
        new_serial = None

        if "serial_number" in self.__config["global"]:
            if self.__config["global"]["serial_number"] == "random":
                found = False
                while not found:
                    new_serial = random.randint(1, self._MAX_SERIAL_NUMBER)
                    if self._has_serial_number(new_serial):
                        found = False
                    else:
                        found = True

            elif self.__config["global"]["serial_number"] == "increment":
                new_serial = self._get_last_serial_number()
                if new_serial:
                    new_serial += 1

        return new_serial

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

    def _store_signature_algorithm(self, cert):
        algoid = None

        algo = {
            "algorithm":"undefined"
        }

        try:
            algo["algorithm"] = cert.get_signature_algorithm()
        except ValueError as error:
            sys.stderr.write("Error: Undefined signature algorithm in certificate data")

        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE signature_algorithm;")
            cursor.execute("SELECT id FROM signature_algorithm WHERE algorithm=%(algorithm)s;", algo)
            result = cursor.fetchall()

            # no entry found?
            if len(result) == 0:
                cursor.execute("INSERT INTO signature_algorithm (algorithm) VALUES (%(algorithm)s);", algo)
                cursor.execute("SELECT id FROM signature_algorithm WHERE algorithm=%(algorithm)s;", algo)
                result = cursor.fetchall()

                algoid = result[0][0]
            algoid = result[0][0]

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't lookup signature algotithm in database: %s\n" % (error.pgerror, ))
            self.__db.rollback()
            return None

        return algoid

    def _store_request(self, csr):

        # dump binary data of signing request
        csr_rawdata = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, csr)
        csr_pkey = hashlib.sha512(csr_rawdata).hexdigest()
        csr_data = {
            "pkey":csr_pkey,
            "request":base64.b64encode(csr_rawdata),
        }

        # check if csr already exists
        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE signing_request;")
            cursor.execute("SELECT COUNT(hash) FROM signing_request WHERE hash='%s'" % (csr_pkey, ))
            searchresult = cursor.fetchall()

            # no entry found, insert data
            if searchresult[0][0] == 0:
                cursor.execute("INSERT INTO signing_request (hash, request) VALUES (%(pkey)s, %(request)s);", csr_data)

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't lookup signing request: %s" % (error.pgerror, ))
            self.__db.rollback()
            return None

        return csr_pkey

    def store_certificate(self, cert, csr=None, revoked=None, replace=False):
        data = self._extract_data(cert, csr, revoked)

        # check if serial_number already exist
        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE certificate")

            if self._has_serial_number(data["serial"]):
                # if the data will not be replaced (the default), return an error if serial number already exists
                if not replace:
                    sys.stderr.write("Error: A certificate with serial number %s (0x%x) already exist\n" %
                                     (data["serial"], data["serial"]))
                    return None

                # data will be replaced
                else:
                    # delete old dataset
                    cursor.execute("DELETE FROM certificate WHERE serial_number=%(serial)s;", data)

            cursor.execute("INSERT INTO certificate (serial_number, version, start_date, end_date, "
                           "subject, fingerprint_md5, fingerprint_sha1, certificate, state, issuer, "
                           "signature_algorithm_id, keysize) VALUES "
                           "(%(serial)s, %(version)s, to_timestamp(%(start_date)s), "
                           "to_timestamp(%(end_date)s), %(subject)s, %(fp_md5)s, %(fp_sha1)s, "
                           "%(pubkey)s, %(state)s, %(issuer)s, %(signature_algorithm_id)s, %(keysize)s);", data)

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

        keysize_statistics = {}
        signature_algorithm_statistics = {}

        try:
            cursor = self.__db.cursor()

            cursor.execute("SELECT state, COUNT(state) FROM certificate GROUP BY state;")
            result = cursor.fetchall()

            for element in result:
                state_statistics[self._certificate_status_reverse_map[element[0]]] = element[1]

            cursor.execute("SELECT keysize, COUNT(keysize) FROM certificate GROUP BY keysize;")
            result = cursor.fetchall()

            for element in result:
                keysize_statistics[element[0]] = element[1]

            cursor.execute("SELECT algorithm, COUNT(algorithm) FROM signature_algorithm INNER JOIN "
                           "certificate ON certificate.signature_algorithm_id=signature_algorithm.id "
                           "GROUP BY algorithm;")
            result = cursor.fetchall()

            for element in result:
                signature_algorithm_statistics[element[0]] = element[1]

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't read certifcate informations from database:%s\n" % (error.pgerror, ))
            self.__db.rollback()
            return None

        statistics["state"] = state_statistics
        statistics["keysize"] = keysize_statistics
        statistics["signature_algorithm"] = signature_algorithm_statistics

        return statistics

    def _insert_empty_cert_data(self, serial, subject):
        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE certificate;")

            # insert empty data to "register" serial number until the
            # signed certificate can be committed
            dummy_data = {
                "serial":serial,
                "subject":subject,
                "state":self._certificate_status_map["temporary"],
            }
            cursor.execute("INSERT INTO certificate (serial_number, subject, state) VALUES "
                           "(%(serial)s, %(subject)s, %(state)s);", dummy_data)

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't insert new serial number into database: %s\n" % (error.pgerror, ))
            self.__db.rollback()
            sys.exit(3)
            return None

    def _get_digest(self):
        if "digest" in self.__config["global"]:
            return self.__config["global"]["digest"]
        else:
            return None

    def remove_certificate(self, serial):
        qdata = {
            "serial":serial,
        }

        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE certificate;")
            cursor.execute("DELETE FROM certificate WHERE serial_number=%(serial)s;", qdata)
            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't remove certificate from database: %s\n", qdata)
            self.__db.rollback()

        return None
