#!/usr/bin/env python
#
# This version is
#   Copyright (C) 2015 Andreas Maus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <https://www.gnu.org/licenses/>.
#


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
from pkidbbackends import Backend

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
                port = int(self.__config["mysql"]["port"])

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
        self.__logger = logging.getLogger("__mysql__")
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
        if not self.__logger:
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
        query = {
            "serial":serial,
        }

        self.__logger.info("Looking for serial number 0x%x in database" % (serial, ))

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number FROM certificate WHERE serial_number=%s;", (query["serial"], ))
            result = cursor.fetchall()

            if len(result) == 0:
                self.__logger.info("Serial number 0x%x was not found in the database" % (serial, ))
                return False
            else:
                self.__logger.info("Serial number 0x%x was found in the database" % (serial, ))
                return True

        except MySQLdb.Error as error:
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
                serial = 0
            else:
                serial = result[0][0]

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't lookup serial number from database: %s" % (error.message, ))
            self.__logger("Can't lookup serial number from database: %s" % (error.message, ))
            self.__db.rollback()
            return None

        self.__logger.info("Last serial number is 0x%x" % (serial, ))
        return result

    def _get_new_serial_number(self, cert):
        new_serial = None

        self.__logger.info("Creating new serial number using method %s" % (self.__config["global"]["serial_number"]))

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

        self.__logger.info("New serial number is 0x%x" % (new_serial, ))
        return new_serial

    def _store_extension(self, extlist):
        result = []

        self.__logger.info("Storing X509 extensions in database")

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
                cursor.execute("SELECT COUNT(hash) FROM extension WHERE hash='%s';" % (pkey, ))
                searchresult = cursor.fetchall()

                # no entry found, insert data
                if searchresult[0][0] == 0:
                    cursor.execute("INSERT INTO extension (hash, name, criticality, data) "
                                   "VALUES (%s, %s, %s, %s);",
                                   (extdata["hash"], extdata["name"], extdata["critical"], extdata["data"]))

                cursor.close()
                self.__db.commit()
                result.append(pkey)
                self.__logger.info("X509 extension stored in 0x%s" % (pkey, ))
            except MySQLdb.Error as error:
                sys.stderr.write("Error: Can't look for extension in database: %s\n" % (error.message, ))
                self.__logger.error("Can't look for extension in database: %s" % (error.message, ))
                self.__db.rollback()
                return None

        self.__logger.info("%u X509 extensions had been stored in the backend" % (len(extlist), ))
        return result

    def _store_signature_algorithm(self, cert):
        algoid = None

        algo = {
            "algorithm":"undefined"
        }

        self.__logger.info("Storing signature algorithm in database")
        try:
            algo["algorithm"] = cert.get_signature_algorithm()
        except ValueError as error:
            self.__logger.warning("Undefined signature algorithm in certificate data")
            sys.stderr.write("Error: Undefined signature algorithm in certificate data\n")

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT id FROM signature_algorithm WHERE algorithm=%s;", (algo["algorithm"], ))
            result = cursor.fetchall()

            # no entry found?
            if len(result) == 0:
                cursor.execute("INSERT INTO signature_algorithm (algorithm) VALUES (%s);", (algo["algorithm"], ))
                cursor.execute("SELECT id FROM signature_algorithm WHERE algorithm=%s;", (algo["algorithm"], ))
                result = cursor.fetchall()

                algoid = result[0][0]
            algoid = result[0][0]

            self.__logger.info("X509 signature algorithm %s stored as %u in database" % (algo["algorithm"], algoid))

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't lookup signature algorithm in database: %s\n" % (error.message, ))
            self.__logger.error("Can't lookup signature algorithm in database: %s" % (error.message, ))
            self.__db.rollback()
            return None

        return algoid

    def _store_request(self, csr):
        self.__logger.info("Storing certificate signing request")

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
            cursor.execute("SELECT COUNT(hash) FROM signing_request WHERE hash='%s'" % (csr_pkey, ))
            searchresult = cursor.fetchall()

            # no entry found, insert data
            if searchresult[0][0] == 0:
                cursor.execute("INSERT INTO signing_request (hash, request) VALUES (%s, %s);",
                               (csr_data["pkey"], csr_data["request"]))

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't lookup signing request: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't lookup signing request: %s" % (error.pgerror, ))
            self.__db.rollback()
            return None

        self.__logger.info("Certificate signing request stored as %s" % (csr_pkey, ))
        return csr_pkey

    def store_certificate(self, cert, csr=None, revoked=None, replace=False, autorenew=None, validity_period=None):
        self.__logger.info("Storing certificate in database")

        data = self._extract_data(cert, csr, revoked)

        # check if serial_number already exist
        try:
            cursor = self.__db.cursor()

            if self._has_serial_number(data["serial"]):
                # if the data will not be replaced (the default), return an error if serial number already exists
                if not replace:
                    sys.stderr.write("Error: A certificate with serial number %s (0x%x) already exist\n" %
                                     (data["serial"], data["serial"]))
                    self.__logger.error("A certificate with serial number %s (0x%x) already exist\n" %
                                        (data["serial"], data["serial"]))
                    return None

                # data will be replaced
                else:
                    # delete old dataset
                    self.__logger.info("Replacement flag set, deleting old certificate with serial number 0x%x" %
                                       (data["serial"], ))
                    cursor.execute("DELETE FROM certificate WHERE serial_number=%s;", (data["serial"], ))

            cursor.execute("INSERT INTO certificate (serial_number, version, start_date, end_date, "
                           "subject, fingerprint_md5, fingerprint_sha1, certificate, state, issuer, "
                           "signature_algorithm_id, keysize) VALUES "
                           "(%s, %s, FROM_UNIXTIME(%s), "
                           "FROM_UNIXTIME(%s), %s, %s, %s, "
                           "%s, %s, %s, %s, %s);",
                           (data["serial"], data["version"], data["start_date"], data["end_date"], data["subject"],
                             data["fp_md5"], data["fp_sha1"], data["pubkey"], data["state"], data["issuer"],
                             data["signature_algorithm_id"], data["keysize"]))

            if "csr" in data:
                self.__logger.info("Certificate signing request found, linking certificate with serial "
                                   "number 0x%x to signing request 0x%s" % (data["serial"], data["csr"]))
                cursor.execute("UPDATE certificate SET signing_request=%s WHERE serial_number=%s;",
                               (data["csr"], data["serial"]))

            if "revreason" in data:
                self.__logger.info("Revocation flag found, set revocation reason to %s with revocation time "
                                   "%s for certificate with serial number 0x%x" % (data["revreason"], data["revtime"],
                                                                                   data["serial"]))
                cursor.execute("UPDATE certificate SET revocation_reason=%s, "
                               "revocation_date=FROM_UNIXTIME(%s), state=%s WHERE "
                               "serial_number=%s;", (data["revreason"], data["revtime"], data["state"], data["serial"]))

            if "extension" in data:
                self.__logger.info("X509 extensions found, storing extensions in database")
                extkeys = self._store_extension(data["extension"])
                if extkeys:
                    # MySQL doesn't support array, convert array to comma separated string instead
                    data["extkey"] = ','.join(extkeys)
                    cursor.execute("UPDATE certificate SET extension=%s WHERE serial_number=%s;",
                                   (data["extkey"], data["serial"]))
                    for ekey in extkeys:
                        self.__logger.info("Linking X509 extension 0x%s to certificate with serial number 0x%s"
                                           % (ekey, data["serial"]))
            cursor.close()
            self.__db.commit()
        except MySQLdb.DatabaseError as error:
            sys.stderr.write("Error: Can't update certificate data in database: %s\n" % (error.message, ))
            self.__logger.error("Error: Can't update certificate data in database: %s" % (error.message, ))
            self.__db.rollback()
            return None

    def housekeeping(self, autorenew=True, validity_period=None, cakey=None):
        self.__logger.info("Running housekeeping")

        try:
            cursor = self.__db.cursor()

            qdata = {
                "valid":self._certificate_status_map["valid"],
                "invalid":self._certificate_status_map["invalid"],
                "expired":self._certificate_status_map["expired"],
                "now":time.time(),
            }

            # if auto renew has been requested get list
            # look for certificates that has been marked as autorenewable
            # and (notAfter - now) < auto_renew_start_period
            if autorenew:
                self.__logger.info("Automatic certificate renew requested, looking for valid certificates marked "
                            "as auto renewable that will in expire in less than auto_renew_start_period days")

                # update autorenew_period was given check this instead
                cursor.execute("SELECT serial_number, extract(EPOCH FROM auto_renew_validity_period) FROM "
                               "certificate WHERE (end_date - now())<auto_renew_start_period AND "
                               "auto_renewable=True AND state=%s;", (qdata["valid"], ))

                result = cursor.fetchall()
                self.__logger.info("Found %u certificates eligible for auto renewal")

                if len(result) > 0:
                    for sn in result:
                        new_start = self._unix_timestamp_to_asn1_time(time.time())
                        if validity_period:
                            self.__logger.info("Using new validity period of %f sec instead of %f sec for renewal"
                                               % (86400. * validity_period, sn[1]))
                            new_end = self._unix_timestamp_to_asn1_time(time.time() + 86400. * validity_period)
                        else:
                            self.__logger.info("Using validity period of %f sec for renewal" % (sn[1], ))
                            new_end = self._unix_timestamp_to_asn1_time(time.time() + sn[1])

                        self.__logger.info("Renewing certificate with serial number 0x%x (notBefore=%s, "
                                           "notAfter=%s)" % (sn[0], new_start, new_end))
                        self.renew_certificate(sn[0], new_start, new_end, cakey)

            # set all invalid certificates to valid if notBefore < now and notAfter > now
            self.__logger.info("Set all invalid certificates to valid if notBefore < now and notAfter > now")
            cursor.execute("SELECT serial_number, start_date, end_date FROM certificate WHERE state=%s AND "
                           "(UNIX_TIMESTAMP(start_date) < %s) AND (UNIX_TIMESTAMP(end_date) > %s);",
                           (qdata["invalid"], qdata["now"], qdata["now"]))

            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from invalid to valid" % (len(result), ))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number 0x%x changed from invalid to valid because "
                                       "(%f < %f) AND (%f > %f)" % (res[0], res[1], qdata["now"], res[2], qdata["now"]))

            cursor.execute("UPDATE certificate SET state=%s WHERE state=%s AND "
                           "(UNIX_TIMESTAMP(start_date) < %s) AND (UNIX_TIMESTAMP(end_date) > %s);",
                           (qdata["valid"], qdata["invalid"], qdata["now"], qdata["now"]))

            # set all valid certificates to invalid if notBefore >= now
            self.__logger.info("Set all valid certificates to invalid if notBefore >= now")
            cursor.execute("SELECT serial_number, start_date FROM certificate WHERE state=%s AND "
                           "(UNIX_TIMESTAMP(start_date) >= %s);", (qdata["valid"], qdata["now"]))
            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from valid to invalid" % (len(result), ))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number 0x%x changed from valid to invalid because "
                                       "(%f >= %f)" % (res[0], res[1], qdata["now"]))

            cursor.execute("UPDATE certificate SET state=%s WHERE state=%s AND "
                           "(UNIX_TIMESTAMP(start_date) >= %s);", (qdata["invalid"], qdata["valid"], qdata["now"]))

            # set all valid certificates to expired if notAfter <= now
            self.__logger.info("Set all valid certificates to expired if notAfter <= now")
            cursor.execute("SELECT serial_number, end_date FROM certificate WHERE state=%s AND "
                           "(UNIX_TIMESTAMP(end_date) <= %s);", (qdata["valid"], qdata["now"]))
            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from valid to expired" % (len(result), ))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number 0x%x changed from valid to expired because "
                                       "(%f <= %f)" % (res[0], res[1], qdata["now"]))

            cursor.execute("UPDATE certificate SET state=%s WHERE state=%s AND "
                           "(UNIX_TIMESTAMP(end_date) <= %s);", (qdata["expired"], qdata["valid"], qdata["now"]))

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't validate certificates: %s\n" % (error.message, ))
            self.__logger.error("Can't validate certificates: %s" % (error.message, ))
            self.__db.rollback()
            return None

    def get_statistics(self):
        self.__logger.info("Getting statistics from database")

        statistics = {}

        state_statistics = {}
        keysize_statistics = {}
        signature_algorithm_statistics = {}
        revocation_statistics = {}

        try:
            cursor = self.__db.cursor()

            self.__logger.info("Getting number of states")
            cursor.execute("SELECT state, COUNT(state) FROM certificate GROUP BY state;")
            result = cursor.fetchall()

            for element in result:
                state_statistics[self._certificate_status_reverse_map[element[0]]] = element[1]

            self.__logger.info("Getting key sizes")
            cursor.execute("SELECT keysize, COUNT(keysize) FROM certificate GROUP BY keysize;")
            result = cursor.fetchall()

            for element in result:
                keysize_statistics[element[0]] = element[1]

            self.__logger.info("Getting signature algorithms")
            cursor.execute("SELECT algorithm, COUNT(algorithm) FROM signature_algorithm INNER JOIN "
                           "certificate ON certificate.signature_algorithm_id=signature_algorithm.id "
                           "GROUP BY algorithm;")
            result = cursor.fetchall()

            for element in result:
                signature_algorithm_statistics[element[0]] = element[1]

            self.__logger.info("Getting revocation reasons")
            cursor.execute("SELECT revocation_reason, COUNT(revocation_reason) FROM certificate "
                           "WHERE state=%u GROUP BY revocation_reason;" % (self._certificate_status_map["revoked"]))
            result = cursor.fetchall()

            for revoked in result:
                reason = self._revocation_reason_reverse_map[revoked[0]]
                revocation_statistics[reason] = revoked[1]

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't read certifcate informations from database:%s\n" % (error.message, ))
            self.__logger.error("Can't read certifcate informations from database:%s" % (error.message, ))
            self.__db.rollback()
            return None

        statistics["state"] = state_statistics
        statistics["keysize"] = keysize_statistics
        statistics["signature_algorithm"] = signature_algorithm_statistics
        statistics["revoked"] = revocation_statistics

        for stat_type in statistics:
            for key in statistics[stat_type]:
                self.__logger.info("%s:%s:%u" % (stat_type, key, statistics[stat_type][key]))

        return statistics

    def _insert_empty_cert_data(self, serial, subject):
        self.__logger.info("Inserting temporary certificate data for serial number 0x%x and subject %s"
                           % (serial, subject))

        try:
            cursor = self.__db.cursor()

            # insert empty data to "register" serial number until the
            # signed certificate can be committed
            dummy_data = {
                "serial":serial,
                "subject":subject,
                "state":self._certificate_status_map["temporary"],
            }
            cursor.execute("INSERT INTO certificate (serial_number, subject, state) VALUES "
                           "(%s, %s, %s);", (dummy_data["serial"], dummy_data["subject"], dummy_data["state"]))

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't insert new serial number into database: %s\n" % (error.message, ))
            self.__logger.error("Can't insert new serial number into database: %s" % (error.message, ))
            self.__db.rollback()
            sys.exit(3)

    def _get_digest(self):
        self.__logger.info("Getting digest algorithm for signature signing from configuration file")
        if "digest" in self.__config["global"]:
            self.__logger.info("Found %s as digest algorithm for signature signing in configuration file" %
                               (self.__config["global"]["digest"]), )
            return self.__config["global"]["digest"]
        else:
            self.__logger.warning("No digest algorithm for signature signing found in configuration file")
            return None

    def remove_certificate(self, serial):
        qdata = {
            "serial":serial,
        }

        self.__logger.info("Removing certificate")

        try:
            cursor = self.__db.cursor()
            cursor.execute("DELETE FROM certificate WHERE serial_number=%s;", (qdata["serial"], ))

            self.__logger.info("Certificate with serial number 0x%x has been removed from the database" % (serial, ))

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't remove certificate from database: %s\n" % (error.message, ))
            self.__logger.error("Can't remove certificate from database: %s" % (error.message, ))
            self.__db.rollback()

        return None

    def generate_revocation_list(self):
        self.__logger.info("Generating certificate revocation list")

        crl = OpenSSL.crypto.CRL()

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number, revocation_reason, UNIX_TIMESTAMP(revocation_date) "
                           "FROM certificate WHERE state=%d" % (self._certificate_status_map["revoked"]))

            result = cursor.fetchall()
            self.__logger.info("%u revoked certificates found in database" % (len(result), ))

            for revoked in result:
                revcert = OpenSSL.crypto.Revoked()
                revcert.set_serial("%x" % (revoked[0], ))
                revcert.set_reason(self._revocation_reason_reverse_map[revoked[1]])
                revcert.set_rev_date(self._unix_timestamp_to_asn1_time(revoked[2]))

                crl.add_revoked(revcert)
                self.__logger.info("Certificate with serial number 0x%x added to revocation list with "
                                   "revocation reason %s and revocation date %s" %
                                   (revoked[0], self._revocation_reason_reverse_map[revoked[1]],
                                    self._unix_timestamp_to_asn1_time(revoked[2])))

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't fetch revoked certificates from backend: %s\n" % (error.message, ))
            self.__logger.error("Can't fetch revoked certificates from backend: %s" % (error.message, ))
            self.__db.rollback()
            return None
        except OpenSSL.crypto.Error as x509error:
            sys.stderr.write("Error: Can't build revocation list: %s\n" % (x509error.message, ))
            self.__logger.error("Can't build revocation list: %s" % (x509error.message, ))
            return None

        return crl

    def revoke_certificate(self, serial, reason, revocation_date):
        try:
            qdata = {
                "serial":serial,
                "reason":self._revocation_reason_map[reason],
                "date":revocation_date,
                "state":self._certificate_status_map["revoked"],
            }

            self.__logger.info("Revoking certificate with serial number 0x%x with revocation reason %s "
                               "and revocation date %s" % (serial, reason, revocation_date))

            cursor = self.__db.cursor()
            cursor.execute("UPDATE certificate SET state=%s, revocation_date=FROM_UNIXTIME(%s), "
                           "revocation_reason=%s WHERE serial_number=%s;",
                           (qdata["state"], qdata["date"], qdata["reason"], qdata["serial"]))
            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't update certifcate in backend: %s\n" % (error.message, ))
            self.__logger.error("Can't update certifcate in backend: %s" % (error.message, ))
            self.__db.rollback()
            return None

        return None

    def get_certificate(self, serial):
        cert = None

        qdata = {
            "serial":serial,
        }

        self.__logger.info("Getting ASN1 data for certificate with serial number 0x%x" % (serial, ))

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT certificate FROM certificate WHERE serial_number=%s;", (qdata["serial"], ))
            result = cursor.fetchall()
            cursor.close()
            self.__db.commit()

            if len(result) == 0:
                return None
            else:
                try:
                    asn1_data = base64.b64decode(result[0][0])
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, asn1_data)
                except OpenSSL.crypto.Error as error:
                    sys.stderr.write("Error: Can't parse ASN1 data: %s\n" % (error.message, ))
                    return None
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't read certificate data from database: %s\n" % (error.message, ))
            self.__logger.error("Can't read certificate data from database: %s" % (error.message, ))
            return None

        return cert

    def _get_state(self, serial):
        try:
            qdata = {
                "serial":serial,
            }

            cursor = self.__db.cursor()
            cursor.execute("SELECT state FROM certificate WHERE serial_number=%s;", (qdata["serial"], ))

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
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't read certificate from database: %s\n" % (error.message, ))
            self.__logger.error("Can't read certificate from database: %s" % (error.message, ))
            return None

    def dump_database(self):
        self.__logger.info("Dumping backend database")
        dump = {}

        try:
            cursor = self.__db.cursor()
            self.__logger.info("Dumping certificate table")

            # dumping certificates
            certdump = []
            cursor.execute("SELECT serial_number, version, UNIX_TIMESTAMP(start_date), "
                           "UNIX_TIMESTAMP(end_date), subject, auto_renewable, "
                           "auto_renew_start_period, "
                           "auto_renew_validity_period, issuer, keysize, fingerprint_md5, "
                           "fingerprint_sha1, certificate, signature_algorithm_id, extension, signing_request, "
                           "state, UNIX_TIMESTAMP(revocation_date), revocation_reason FROM certificate;")
            result = cursor.fetchall()
            self.__logger.info("Dumping %u certificates" % (len(result), ))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Dumping certificate with serial number 0x%x" % (res[0], ))
                    # check if extension row is not empty
                    if res[14]:
                        entry = {
                            "serial_number":str(res[0]),
                            "version":res[1],
                            "start_date":res[2],
                            "end_date":res[3],
                            "subject":res[4],
                            "auto_renewable":res[5],
                            "auto_renew_start_period":res[6],
                            "auto_renew_validity_period":res[7],
                            "issuer":res[8],
                            "keysize":res[9],
                            "fingerprint_md5":res[10],
                            "fingerprint_sha1":res[11],
                            "certificate":res[12],
                            "signature_algorithm_id":res[13],

                            # split comma separated string of extensions into an array
                            "extension":res[14].split(","),

                            "signing_request":res[15],
                            "state":res[16],
                            "revocation_date":res[17],
                            "revocation_reason":res[18],
                        }
                    else:
                        entry = {
                            "serial_number":str(res[0]),
                            "version":res[1],
                            "start_date":res[2],
                            "end_date":res[3],
                            "subject":res[4],
                            "auto_renewable":res[5],
                            "auto_renew_start_period":res[6],
                            "auto_renew_validity_period":res[7],
                            "issuer":res[8],
                            "keysize":res[9],
                            "fingerprint_md5":res[10],
                            "fingerprint_sha1":res[11],
                            "certificate":res[12],
                            "signature_algorithm_id":res[13],
                            "extension":res[14],
                            "signing_request":res[15],
                            "state":res[16],
                            "revocation_date":res[17],
                            "revocation_reason":res[18],
                        }

                    # convert "boolean" from MySQL into REAL booleans
                    if entry["auto_renewable"] == 0:
                        entry["auto_renewable"] = False
                    elif entry["auto_renewable"] == 1:
                        entry["auto_renewable"] = True

                    certdump.append(entry)
            dump["certificate"] = certdump

            # dumping x509 extensions
            extdump = []
            cursor.execute("SELECT hash, name, criticality, data FROM extension;")
            result = cursor.fetchall()
            self.__logger.info("Dumping %u extensions" % (len(result), ))
            if len(result) > 0:
                for res in result:
                    self.__logger.info("Dumping extension with key id %s" % (res[0], ))
                    entry = {
                        "hash":res[0],
                        "name":res[1],
                        "criticality":res[2],
                        "data":res[3],
                    }

                    # convert "boolean" from MySQL into REAL booleans
                    if entry["criticality"] == 0:
                        entry["criticality"] = False
                    elif entry["criticality"] == 1:
                        entry["criticality"] = True

                    extdump.append(entry)
            dump["extension"] = extdump

            # dumping signature algorithms
            self.__logger.info("Dumping list of signature algorithms")

            algodump = []
            cursor.execute("SELECT id, algorithm FROM signature_algorithm;")
            result = cursor.fetchall()
            self.__logger.info("Dumping %u signature algorithms" % (len(result), ))

            if len(result)>0:
                for res in result:
                    self.__logger.info("Dumping signing algorithm %s with id %u" % (res[1], res[0]))
                    entry = {
                        "id":str(res[0]),
                        "algorithm":res[1],
                    }
                    algodump.append(entry)
            dump["signature_algorithm"] = algodump

            # dumping certificate signing requests
            csrdump = []
            cursor.execute("SELECT hash, request FROM signing_request;")
            result = cursor.fetchall()

            self.__logger.info("Dumping %u certificate signing requests" % (len(result), ))
            if len(result)>0:
                for res in result:
                    self.__logger.info("Dumping signing request %s" % (res[0], ))
                    entry = {
                        "hash":res[0],
                        "request":res[1],
                    }
                    csrdump.append(entry)

            dump["signing_request"] = csrdump

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            sys.stderr.write("Error: Can't read from backend database: %s\n" % (error.message, ))
            self.__logger.error("Can't read from backend database: %s" % (error.message, ))
            self.__db.rollback()
            return None

        return dump

    def list_serial_number_by_state(self, state):
        sn_list =  []

        if state:
            qdata = {
                "state":self._certificate_status_map[state],
            }

            self.__logger.info("Getting serial numbers for certificates with state %u" % (qdata["state"], ))
            try:
                cursor = self.__db.cursor()
                cursor.execute("SELECT serial_number FROM certificate WHERE state=%s;", (qdata["state"], ))

                result = cursor.fetchall()
                for res in result:
                    self.__logger.info("Adding serial number 0x%x to result list" % (res[0], ))
                    sn_list.append(str(res[0]))

                cursor.close()
                self.__db.commit()
            except sqlite3.Error as error:
                self.__logger.error("Can't get list of serial numbers: %s" % (error.message, ))
                sys.stderr.write("Error: Can't get list of serial numbers: %s" % (error.message, ))
                return None
        else:
            self.__logger.info("Getting all serial numbers")
            try:
                cursor = self.__db.cursor()
                cursor.execute("SELECT serial_number FROM certificate;")

                result = cursor.fetchall()
                for res in result:
                    self.__logger.info("Adding serial number 0x%x to result list" % (res[0], ))
                    sn_list.append(str(res[0]))

                cursor.close()
                self.__db.commit()
            except MySQLdb.Error as error:
                self.__logger.error("Can't get list of serial numbers: %s" % (error.message, ))
                sys.stderr.write("Error: Can't get list of serial numbers: %s" % (error.message, ))
                return None

        return sn_list

    def restore_database(self, dump):
        try:
            cursor = self.__db.cursor()
            # restore certificate table
            self.__logger.info("Restoring certificate table")
            for cert in dump["certificate"]:
                # MySQL can't handle arrays so we create a commma separated string from the array
                if cert["extension"]:
                    cert["extension"] = ",".join(cert["extension"])

                cursor.execute("INSERT INTO certificate (serial_number, version, start_date, "
                               "end_date, subject, auto_renewable, "
                               "auto_renew_start_period, "
                               "auto_renew_validity_period, issuer, keysize, fingerprint_md5, "
                               "fingerprint_sha1, certificate, signature_algorithm_id, extension, signing_request, "
                               "state, revocation_date, revocation_reason) "
                               "VALUES(%s, %s, FROM_UNIXTIME(%s), "
                               "FROM_UNIXTIME(%s), %s, %s, "
                               "%s, "
                               "%s, %s, %s, "
                               "%s, %s, %s, "
                               "%s, %s, %s, "
                               "%s, FROM_UNIXTIME(%s), %s);",
                               (cert["serial_number"], cert["version"], cert["start_date"], cert["end_date"],
                                cert["subject"], cert["auto_renewable"], cert["auto_renew_start_period"],
                                cert["auto_renew_validity_period"], cert["issuer"], cert["keysize"],
                                cert["fingerprint_md5"], cert["fingerprint_sha1"], cert["certificate"],
                                cert["signature_algorithm_id"], cert["extension"], cert["signing_request"],
                                cert["state"], cert["revocation_date"], cert["revocation_reason"]))

            self.__logger.info("%u rows restored for certificate table" % (len(dump["certificate"]), ))

            # restore extension table
            self.__logger.info("Restoring extension table")
            for ext in dump["extension"]:
                cursor.execute("INSERT INTO extension (hash, name, criticality, data) VALUES "
                               "(%s, %s, %s, %s);", (ext["hash"], ext["name"], ext["criticality"], ext["data"]))
            self.__logger.info("%u rows restored for extension table" % (len(dump["extension"]), ))

            # restore signing_request table
            self.__logger.info("Restoring signing_request table")
            for csr in dump["signing_request"]:
                cursor.execute("INSERT INTO signing_request (hash, request) VALUES "
                               "(%s, %s);", (csr["hash"], csr["request"]))
            self.__logger.info("%u rows restored for signing_request table" % (len(dump["signing_request"]), ))

            # restore signature_algorithm
            self.__logger.info("Restoring signature_algorithm table")
            for sigalgo in dump["signature_algorithm"]:
                cursor.execute("INSERT INTO signature_algorithm (id, algorithm) "
                                "VALUES (%s, %s);", (sigalgo["id"], sigalgo["algorithm"]))
            self.__logger.info("%u rows restored for signature_algorithm table" % (len(dump["signature_algorithm"]), ))

            # fetch last sequence number
            cursor.execute("SELECT id FROM signature_algorithm ORDER BY id DESC LIMIT 1;")
            result = cursor.fetchall()
            # if table is empty start at 1
            if len(result) == 0:
                newsequence = 1
            else:
                newsequence = long(result[0][0]) + 1

            self.__logger.info("Readjusting primary key counter to %u" % (newsequence, ))
            cursor.execute("ALTER TABLE signature_algorithm AUTO_INCREMENT=%u;" % (newsequence, ))

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            self.__logger.error("Can't restore database from dump: %s" % (error.message, ))
            sys.stderr.write("Error: Can't restore database from dump: %s\n" % (error.message, ))
            return False

        return True

    def get_certificate_data(self, serial):
        data = {
            "serial_number":None,
            "version":None,
            "start_date":None,
            "end_date":None,
            "subject":None,
            "auto_renewable":None,
            "auto_renew_start_period":None,
            "auto_renew_validity_period":None,
            "issuer":None,
            "keysize":None,
            "fingerprint_md5":None,
            "fingerprint_sha1":None,
            "certificate":None,
            "algorithm":None,
            "extension":None,
            "signing_request":None,
            "state":None,
            "revocation_date":None,
            "revocation_reason":None,
        }
        qdata = { "serial":serial }

        try:
            cursor = self.__db.cursor()
            # we can't do a second INNER JOIN on signing_request because it may be NULL
            cursor.execute("SELECT serial_number, version, start_date, "
                           "end_date, subject, auto_renewable, "
                           "auto_renew_start_period, "
                           "auto_renew_validity_period, issuer, keysize, fingerprint_md5, "
                           "fingerprint_sha1, certificate, algorithm, extension, signing_request, "
                           "state, revocation_date, revocation_reason "
                           "FROM certificate INNER JOIN signature_algorithm ON signature_algorithm_id=id "
                           "WHERE serial_number=%s;", (qdata["serial"], ))
            result = cursor.fetchall()
            if len(result) > 0:
                data = {
                    "serial_number":"%u (0x%02x)" % (long(result[0][0]), long(result[0][0]) ),
                    "version":result[0][1] + 1,
                    "start_date":time.strftime("%a, %d %b %Y %H:%M:%S %z", time.localtime(result[0][2])),
                    "end_date":time.strftime("%a, %d %b %Y %H:%M:%S %z", time.localtime(result[0][3])),
                    "subject":result[0][4],
                    "auto_renewable":result[0][5],
                    "issuer":result[0][8],
                    "keysize":result[0][9],
                    "fingerprint_md5":result[0][10],
                    "fingerprint_sha1":result[0][11],
                    "certificate":result[0][12],
                    "algorithm":result[0][13],
                    "extension":result[0][14],
                    "signing_request":result[0][15],
                    "state":self._certificate_status_reverse_map[result[0][16]],

                }

                if data["state"] == "revoked":
                    data["revocation_date"] = time.strftime("%a, %d %b %Y %H:%M:%S %z", time.localtime(result[0][17]))
                    data["revocation_reason"] = self._revocation_reason_reverse_map[result[0][18]]

                # convert 0/1 to real boolean False/True
                if data["auto_renewable"] == 1:
                    data["auto_renewable"] = True
                    data["auto_renew_start_period"] = result[0][6]
                    data["auto_renew_validity_period"] = result[0][7]
                else:
                    data["auto_renewable"] = False

                if data["signing_request"]:
                    cursor.execute("SELECT request FROM signing_request WHERE hash=%s;", (data["signing_request"], ))
                    csr_result = cursor.fetchall()
                    data["signing_request"] = csr_result[0][0]

                if data["extension"]:
                    extlist = []
                    # convert comma separated list to an array
                    data["extension"] = data["extension"].split(",")
                    for ext in data["extension"]:
                        qext = { "hash":ext }
                        cursor.execute("SELECT name, criticality, data FROM extension WHERE hash=%s;", (qext["hash"], ))
                        ext_result = cursor.fetchall()
                        extlist.append({ "name":ext_result[0][0], "critical":ext_result[0][1], "data":ext_result[0][2]})
                    data["extension"] = extlist
                else:
                    data["extension"] = []
            else:
                data = None

            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            self.__logger.error("Can't lookup certificate with serial number %s in database: %s"
                                % (serial, error.message))
            sys.stderr.write("Error: Can't lookup certificate with serial number %s in database: %s"
                             % (serial, error.message))
            self.__db.rollback()
            return None
        return data

    # FIXME: Eligible for move to parent class
    def _get_from_config_global(self, option):
        if option in self.__config["global"]:
            return self.__config["global"][option]
        else:
            return None

    def set_certificate_metadata(self, serial, auto_renew=None, auto_renew_start_period=None,
                                 auto_renew_validity_period=None):

        if auto_renew == None and not auto_renew_start_period and not auto_renew_validity_period:
            return False

        if not self.get_certificate(serial):
            return None

        try:
            cursor = self.__db.cursor()

            qdata = {
                "serial":serial,
                "auto_renewable":auto_renew,
                "auto_renew_start_period":auto_renew_start_period,
                "auto_renew_validity_period":auto_renew_validity_period,
            }

            if auto_renew == None:
                # setting auto_renew_start_period or auto_renew_validity_period implicitly sets the auto_renew flag
                if auto_renew_start_period or auto_renew_validity_period:
                    qdata["auto_renewable"] = True
                    auto_renew = True

                if auto_renew_start_period:
                    qdata["auto_renew_start_period"] = float(qdata["auto_renew_start_period"]) * 86400.
                    cursor.execute("UPDATE certificate SET "
                                   "auto_renew_start_period=%s, "
                                   "auto_renewable=%s WHERE serial_number=%s;",
                                   (qdata["auto_renew_start_period"], qdata["auto_renewable"], qdata["serial"]))

                    self.__logger.info("Setting auto_renew_start_period of certificate 0x%x to %f days." %
                                       (serial, qdata["auto_renew_start_period"]/86400.))
                    udata = {
                        "serial":serial,
                    }
                    # set auto_renew_validity_period to validity_period of not set
                    if not auto_renew_validity_period:
                        udata["auto_renew_validity_period"] = float(self._get_from_config_global("validity_period")) \
                                                              * 86400
                        cursor.execute("UPDATE certificate SET "
                                       "auto_renew_validity_period=%s "
                                       "WHERE serial_number=%s AND auto_renew_validity_period IS NULL;",
                                       (udata["auto_renew_validity_period"], udata["serial"]))
                        self.__logger.info("Setting auto_renew_validity_period to %f days if not already set." %
                                           (udata["auto_renew_validity_period"]/86400., ))

                if auto_renew_validity_period:
                    qdata["auto_renew_validity_period"] = float(qdata["auto_renew_validity_period"]) * 86400.
                    cursor.execute("UPDATE certificate SET "
                                   "auto_renew_validity_period=%s, "
                                   "auto_renewable=%s WHERE serial_number=%s;",
                                   (qdata["auto_renew_validity_period"], qdata["auto_renewable"], qdata["serial"]))

                    self.__logger.info("Setting auto_renew_validity_period of certificate 0x%x to %f days." %
                                       (serial, qdata["auto_renew_validity_period"]/86400.))

                    udata = {
                        "serial":serial,
                    }
                    # set auto_renew_start_period to validity_period of not set
                    if not auto_renew_start_period:
                        udata["auto_renew_start_period"] = float(self._get_from_config_global("autorenew_delta")) \
                                                              * 86400.
                        cursor.execute("UPDATE certificate SET "
                                       "auto_renew_start_period=%s "
                                       "WHERE serial_number=%s AND auto_renew_start_period IS NULL;",
                                       (udata["auto_renew_start_period"], udata["serial"]))
                        self.__logger.info("Setting auto_renew_start_period to %f days if not already set." %
                                           (udata["auto_renew_start_period"]/86400., ))

            if auto_renew == True:
                # setting auto_renewable flag also sets auto_renew_start_period and auto_renew_validity_period
                if not auto_renew_start_period:
                    auto_renew_start_period = float(self._get_from_config_global("autorenew_delta")) * 86400.
                    self.__logger.info("Setting auto_renew_start_period from configuration file to %s" %
                                       (auto_renew_start_period, ))

                    if not auto_renew_start_period:
                        self.__logger.error("Can't lookup option autorenew_delta from configuration file.")
                        sys.stderr.write("Error: Can't lookup option autorenew_delta from configuration file.\n")
                        cursor.close()
                        self.__db.rollback()
                        sys.exit(3)

                    qdata["auto_renew_start_period"] = auto_renew_start_period

                if not auto_renew_validity_period:
                    auto_renew_validity_period = float(self._get_from_config_global("validity_period")) * 86400.
                    self.__logger.info("Setting auto_renew_validity_period from configuration file to %s" %
                                       (auto_renew_validity_period/86400., ))

                    if not auto_renew_validity_period:
                        self.__logger.error("Can't lookup validity_period from configuration file.")
                        sys.stderr.write("Error: Can't lookup validity_period from configuration file.\n")
                        cursor.close()
                        self.__db.rollback()
                        sys.exit(3)
                    qdata["auto_renew_validity_period"] = auto_renew_validity_period

                    cursor.execute("UPDATE certificate SET auto_renewable=%s, "
                                   "auto_renew_start_period=%s, "
                                   "auto_renew_validity_period=%s "
                                   "WHERE serial_number=%s;",
                                   (qdata["auto_renewable"], qdata["auto_renew_start_period"],
                                    qdata["auto_renew_validity_period"], qdata["serial"]))

                    self.__logger.info("Setting auto_renewable to %s (auto_renew_start_period is %s days and "
                                       "auto_renew_validity_period is %s days)" %
                                       (qdata["auto_renewable"], qdata["auto_renew_start_period"]/86400.,
                                        qdata["auto_renew_validity_period"]/86400.))

            # explicitly check for False to avoid None
            elif auto_renew == False:
                # disabling auto_renew flag also removes auto_renew_start_period and auto_renew_validity_period
                qdata["auto_renew_start_period"] = None
                qdata["auto_renew_validity_period"] = None
                cursor.execute("UPDATE certificate SET auto_renewable=%s, "
                               "auto_renew_start_period=NULL, auto_renew_validity_period=NULL "
                               "WHERE serial_number=%s;", (qdata["auto_renewable"], qdata["serial"]))
            cursor.close()
            self.__db.commit()
        except MySQLdb.Error as error:
            self.__logger.error("Can't update auto_renew parameters: %s" % (error.message, ))
            sys.stderr.write("Error: Can't update auto_renew parameters: %s\n" % (error.message, ))
            return None

        return True
