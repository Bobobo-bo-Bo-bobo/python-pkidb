#!/usr/bin/env python


import base64
import hashlib
import logging
import logging.handlers
import os
import psycopg2
import random
import sys
import time
import OpenSSL
from backends import Backend

class PostgreSQL(Backend):
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
        super(PostgreSQL, self).__init__(config)

        self.__init_logger()
        self.__config = config
        self.__db = self.__connect(config)
        if not self.__db:
            self.__logger.error("Unable to connect to database")
            sys.exit(4)

    def __del__(self):
        super(PostgreSQL, self).__del__()
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
            cursor.execute("LOCK TABLE certificate;")
            cursor.execute("SELECT serial_number FROM certificate WHERE serial_number=%(serial)s;", query)
            result = cursor.fetchall()

            if len(result) == 0:
                self.__logger.info("Serial number 0x%x was not found in the database")
                return False
            else:
                self.__logger.info("Serial number 0x%x was found in the database")
                return True

        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't query database for serial number: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't query database for serial number: %s" % (error.pgerror, ))
            return None

        # Never reached
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
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't lookup serial number from database: %s" % (error.pgerror, ))
            self.__logger("Can't lookup serial number from database: %s" % (error.pgerror, ))
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
                self.__logger.info("X509 extension stored in 0x%x" % (pkey, ))
            except psycopg2.Error as error:
                sys.stderr.write("Error: Can't look for extension in database: %s\n" % (error.pgerror, ))
                self.__logger.error("Can't look for extension in database: %s" % (error.pgerror, ))
                self.__db.rollback()
                return None

        sys.__logger.info("%u X509 extensions are had been stored in the backend")
        return result

    def _store_signature_algorithm(self, cert):
        algoid = None

        algo = {
            "algorithm":"undefined"
        }

        sys.__logger.info("Storing signature algorithm in database")
        try:
            algo["algorithm"] = cert.get_signature_algorithm()
        except ValueError as error:
            self.__logger.warning("Undefined signature algorithm in certificate data")
            sys.stderr.write("Error: Undefined signature algorithm in certificate data\n")

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

            self.__logger.info("X509 signature algorithm %s stored as %u in database" % (algo["algorithm"], algoid))

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't lookup signature algorithm in database: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't lookup signature algorithm in database: %s" % (error.pgerror, ))
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
            cursor.execute("LOCK TABLE signing_request;")
            cursor.execute("SELECT COUNT(hash) FROM signing_request WHERE hash='%s'" % (csr_pkey, ))
            searchresult = cursor.fetchall()

            # no entry found, insert data
            if searchresult[0][0] == 0:
                cursor.execute("INSERT INTO signing_request (hash, request) VALUES (%(pkey)s, %(request)s);", csr_data)

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
            cursor.execute("LOCK TABLE certificate")

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
                    cursor.execute("DELETE FROM certificate WHERE serial_number=%(serial)s;", data)

            cursor.execute("INSERT INTO certificate (serial_number, version, start_date, end_date, "
                           "subject, fingerprint_md5, fingerprint_sha1, certificate, state, issuer, "
                           "signature_algorithm_id, keysize) VALUES "
                           "(%(serial)s, %(version)s, to_timestamp(%(start_date)s), "
                           "to_timestamp(%(end_date)s), %(subject)s, %(fp_md5)s, %(fp_sha1)s, "
                           "%(pubkey)s, %(state)s, %(issuer)s, %(signature_algorithm_id)s, %(keysize)s);", data)

            if "csr" in data:
                self.__logger.info("Certificate signing request found, linking certificate with serial "
                                   "number 0x%x to signing request 0x%x" % (data["serial"], data["csr"]))
                cursor.execute("UPDATE certificate SET signing_request=%(csr)s WHERE serial_number=%(serial)s;", data)

            if "revreason" in data:
                self.__logger.info("Revocation flag found, set revocation reason to %s with revocation time "
                                   "%s for certificate with serial number 0x%x" % (data["revreason"], data["revtime"],
                                                                                   data["serial"]))
                cursor.execute("UPDATE certificate SET revocation_reason=%(revreason)s, "
                               "revocation_date=to_timestamp(%(revtime)s), state=%(state)s WHERE "
                               "serial_number=%(serial)s;", data)

            if "extension" in data:
                self.__logger.info("X509 extensions found, storing extensions in database")
                extkeys = self._store_extension(data["extension"])
                if extkeys:
                    data["extkey"] = extkeys
                    cursor.execute("UPDATE certificate SET extension=%(extkey)s WHERE serial_number=%(serial)s;", data)
                    for ekey in extkeys:
                        self.__logger.info("Linking X509 extension 0x%x to certificate with serial number 0x%x"
                                           % (ekey, data["serial"]))
            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't update certificate data in database: %s\n" % (error.pgerror, ))
            self.__logger.error("Error: Can't update certificate data in database: %s" % (error.pgerror, ))
            self.__db.rollback()
            return None

    def housekeeping(self, autorenew=True, validity_period=None, cakey=None):
        self.__logger.info("Running housekeeping")

        try:
            cursor = self.__db.cursor()
            cursor.execute("LOCK TABLE certificate;")

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
                               "auto_renewable=True AND state=%(valid)s;", qdata)

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
            cursor.execute("SELECT serial_number, start_date, end_date FROM certificate WHERE state=%(invalid)s AND "
                           "(start_date < to_timestamp(%(now)s)) AND (end_date > to_timestamp(%(now)s));", qdata)
            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from invalid to valid" % (len(result), ))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number 0x%x changed from invalid to valid because "
                                       "(%f < %f) AND (%f > %f)" % (res[0], res[1], qdata["now"], res[2], qdata["now"]))

            cursor.execute("UPDATE certificate SET state=%(valid)s WHERE state=%(invalid)s AND "
                           "(start_date < to_timestamp(%(now)s)) AND (end_date > to_timestamp(%(now)s));", qdata)

            # set all valid certificates to invalid if notBefore >= now
            self.__logger.info("Set all valid certificates to invalid if notBefore >= now")
            cursor.execute("SELECT serial_number, start_date FROM certificate WHERE state=%(valid)s AND "
                           "(start_date >= to_timestamp(%(now)s));", qdata)
            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from valid to invalid" % (len(result), ))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number 0x%x changed from valid to invalid because "
                                       "(%f >= %f)" % (res[0], res[1], qdata["now"]))

            cursor.execute("UPDATE certificate SET state=%(invalid)s WHERE state=%(valid)s AND "
                           "(start_date >= to_timestamp(%(now)s));", qdata)

            # set all valid certificates to expired if notAfter <= now
            self.__logger.info("Set all valid certificates to expired if notAfter <= now")
            cursor.execute("SELECT serial_number, end_date FROM certificate WHERE state=%(valid)s AND "
                           "(end_date <= to_timestamp(%(now)s));", qdata)
            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from valid to expired" % (len(result), ))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number 0x%x changed from valid to expired because "
                                       "(%f <= %f)" % (res[0], res[1], qdata["now"]))

            cursor.execute("UPDATE certificate SET state=%(expired)s WHERE state=%(valid)s AND "
                           "(end_date <= to_timestamp(%(now)s));", qdata)

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't validate certificates: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't validate certificates: %s" % (error.pgerror, ))
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
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't read certifcate informations from database:%s\n" % (error.pgerror, ))
            self.__logger.error("Can't read certifcate informations from database:%s" % (error.pgerror, ))
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
            self.__logger.error("Can't insert new serial number into database: %s" % (error.pgerror, ))
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
            cursor.execute("LOCK TABLE certificate;")
            cursor.execute("DELETE FROM certificate WHERE serial_number=%(serial)s;", qdata)

            self.__logger.info("Certificate with serial number 0x%x has been removed from the database" % (serial, ))

            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't remove certificate from database: %s\n" % (serial, ))
            self.__logger.error("Can't remove certificate from database: %s" % (serial, ))
            self.__db.rollback()

        return None

    def generate_revocation_list(self):
        self.__logger.info("Generating certificate revocation list")

        crl = OpenSSL.crypto.CRL()

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number, revocation_reason, extract(EPOCH from revocation_date) "
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
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't fetch revoked certificates from backend: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't fetch revoked certificates from backend: %s" % (error.pgerror, ))
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
            cursor.execute("LOCK TABLE certificate;")
            cursor.execute("UPDATE certificate SET state=%(state)s, revocation_date=to_timestamp(%(date)s), "
                           "revocation_reason=%(reason)s WHERE serial_number=%(serial)s;", qdata)
            cursor.close()
            self.__db.commit()
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't update certifcate in backend: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't update certifcate in backend: %s" % (error.pgerror, ))
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
            cursor.execute("SELECT certificate FROM certificate WHERE serial_number=%(serial)s;", qdata)
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
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't read certificate data from database: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't read certificate data from database: %s" % (error.pgerror, ))
            return None

        return cert

    def renew_certificate(self, serial, notBefore, notAfter, cakey):
        self.__logger.info("Renewing certificate with serial number 0x%x" % (serial, ))

        # check if the certificate has been revoked
        if self._is_revoked(serial):
            sys.stderr.write("Error: Certificate with serial number %s can't be renewed, "
                             "it has been revoked\n" % (serial, ))
            self.__logger.error("Certificate with serial number 0x%x can't be renewed, "
                                "it has been revoked" % (serial, ))
            return None

        newcert = self.get_certificate(serial)
        if newcert:

            # set new validity dates
            newcert.set_notBefore(notBefore)
            newcert.set_notAfter(notAfter)

            # resign certificate using the same signature algorithm
            newcert.sign(cakey, newcert.get_signature_algorithm())

            self.__logger.info("Certificate with serial number 0x%x is now valid from %s til %s" %
                               (serial, notBefore, notAfter))

            # commit new certificate
            self.store_certificate(newcert, replace=True)

        return newcert

    def _get_state(self, serial):
        try:
            qdata = {
                "serial":serial,
            }

            cursor = self.__db.cursor()
            cursor.execute("SELECT state FROM certificate WHERE serial_number=%(serial)s;", qdata)

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
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't read certificate from database: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't read certificate from database: %s" % (error.pgerror, ))
            return None

    def dump_database(self):
        self.__logger.info("Dumping backend database")
        dump = {}

        try:
            cursor = self.__db.cursor()
            self.__logger.info("Dumping certificate table")

            # dumping certificates
            certdump = []
            cursor.execute("LOCK TABLE certificate;")
            cursor.execute("SELECT serial_number, version, extract(EPOCH FROM start_date), "
                           "extract(EPOCH FROM end_date), subject, auto_renewable, "
                           "extract(EPOCH FROM auto_renew_start_period), "
                           "extract(EPOCH FROM auto_renew_validity_period), issuer, keysize, fingerprint_md5, "
                           "fingerprint_sha1, certificate, signature_algorithm_id, extension, signing_request, "
                           "state, extract(EPOCH FROM revocation_date), revocation_reason FROM certificate;")
            result = cursor.fetchall()
            self.__logger.info("Dumping %u certificates" % (len(result), ))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Dumping certificate with serial number 0x%x" % (res[0], ))
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
                    certdump.append(entry)
            dump["certificate"] = certdump

            # dumping x509 extensions
            extdump = []
            cursor.execute("LOCK TABLE extension;")
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
                    extdump.append(entry)
            dump["extension"] = extdump

            # dumping signature algorithms
            self.__logger.info("Dumping list of signature algorithms")

            algodump = []
            cursor.execute("LOCK TABLE signature_algorithm;")
            cursor.execute("SELECT id, algorithm FROM signature_algorithm;")
            result = cursor.fetchall()
            self.__logger.info("Dumping %u signature algorithms" % (len(result), ))

            if len(result)>0:
                for res in result:
                    self.__logger.info("Dumping signing algorithm %s with id %u" % (res[1], res[0]))
                    entry = {
                        "id":res[0],
                        "signature_algorithm":res[1],
                    }
                    algodump.append(entry)
            dump["signature_algorithm"] = algodump

            # dumping certificate signing requests
            csrdump = []
            cursor.execute("LOCK TABLE signing_request;")
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
        except psycopg2.Error as error:
            sys.stderr.write("Error: Can't read from backend database: %s\n" % (error.pgerror, ))
            self.__logger.error("Can't read from backend database: %s" % (error.pgerror, ))
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
                cursor.execute("SELECT serial_number FROM certificate WHERE state=%(state)s;", qdata)

                result = cursor.fetchall()
                for res in result:
                    self.__logger.info("Adding serial number 0x%x to result list" % (res[0], ))
                    sn_list.append(str(res[0]))

                cursor.close()
                self.__db.commit()
            except psycopg2.Error as error:
                self.__logger.error("Can't get list of serial numbers: %s" % (error.pgerror, ))
                sys.stderr.write("Error: Can't get list of serial numbers: %s" % (error.pgerror, ))
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
            except psycopg2.Error as error:
                self.__logger.error("Can't get list of serial numbers: %s" % (error.pgerror, ))
                sys.stderr.write("Error: Can't get list of serial numbers: %s" % (error.pgerror, ))
                return None

        return sn_list
