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
import sqlite3
import random
import re
import sys
import time
import OpenSSL
from pkidbbackends import Backend, PKIDBException


class SQLite(Backend):
    __db = None
    __config = None
    __logger = None

    def __init_logger(self, options):
        name = os.path.basename(sys.argv[0])
        logformat = logging.Formatter(name + " %(name)s:%(lineno)d %(levelname)s: %(message)s")
        re_logging = re.compile("(\w+),(\w+):(.*)$")

        self.__logger = logging.getLogger("sqlite")
        self.__logger.setLevel(logging.INFO)

        if "logging" in options:

            for log in options["logging"]:
                if re_logging.match(options["logging"][log]):
                    (level, logtype, logoptions) = re_logging.match(options["logging"][log]).groups()

                    if logtype.lower() == "file":
                        handler = logging.FileHandler(logoptions)
                        handler.setLevel(self._get_loglevel(level))
                        flogformat = logging.Formatter("%(asctime)s " + name +
                                                       " %(name)s:%(lineno)d %(levelname)s: %(message)s",
                                                       datefmt='%d %b %Y %H:%M:%S')
                        handler.setFormatter(flogformat)
                        self.__logger.addHandler(handler)
                    elif logtype.lower() == "syslog":
                        handler = logging.handlers.SysLogHandler(address="/dev/log", facility=logoptions.lower())
                        handler.setLevel(self._get_loglevel(level))
                        handler.setFormatter(logformat)
                        handler.setLevel(logging.INFO)

                        self.__logger.addHandler(handler)
                    else:
                        sys.stderr.write("Error: Unknown logging mechanism %s\n" % (logtype,))
        else:
            # set default logging
            # initialize logging subsystem

            handler = logging.handlers.SysLogHandler(address='/dev/log')
            handler.setLevel(logging.INFO)
            handler.setFormatter(logformat)

            self.__logger.addHandler(handler)

    def __connect(self, config):
        try:
            db = sqlite3.connect(config["sqlite3"]["database"])
        except sqlite3.Error as error:
            self.__logger.error("Can't connect to database %s: %s" % (config["sqlite3"]["database"], error.message))
            raise PKIDBException(message="Can't connect to database %s: %s" %
                                         (config["sqlite3"]["database"], error.message))

        return db

    def __init__(self, config):
        super(SQLite, self).__init__(config)

        self.__config = config
        if not self.__logger:
            self.__init_logger(self.__config)

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
            qdata = (serial,)

            cursor = self.__db.cursor()
            cursor.execute("SELECT state FROM certificate WHERE serial_number=?;", qdata)

            self.__logger.info("Getting state for certificate with serial number %s" % (str(serial),))

            result = cursor.fetchall()
            cursor.close()
            self.__db.commit()

            if len(result) > 0:
                self.__logger.info("Certificate with serial number %s is %s" %
                                   (str(serial), self._certificate_status_reverse_map[result[0][0]]))

                return result[0][0]
            else:
                self.__logger.warning("No certificate with serial number %s found in database" %
                                      (str(serial),))
                return None
        except sqlite3.Error as error:
            self.__logger.error("Can't read certificate from database: %s" % (error.message,))
            raise PKIDBException(message="Can't read certificate from database: %s" % (error.message,))

    def _has_serial_number(self, serial):
        query = (serial,)

        self.__logger.info("Looking for serial number %s in database" % (str(serial),))

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number FROM certificate WHERE serial_number=?;", query)
            result = cursor.fetchall()

            if len(result) == 0:
                self.__logger.info("Serial number %s was not found in the database" % (str(serial),))
                return False
            else:
                self.__logger.info("Serial number %s was found in the database" % (str(serial),))
                return True

        except sqlite3.Error as error:
            self.__logger.error("Can't query database for serial number: %s" % (error.message,))
            raise PKIDBException(message="Can't query database for serial number: %s\n" % (error.message,))

    def _get_last_serial_number(self):

        self.__logger.info("Looking for last serial number")
        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT MAX(serial_number) FROM;")
            result = cursor.fetchall()
            if len(result) == 0:
                self.__logger.error("No serial number found in database")
                raise PKIDBException(message="No serial number found in database")

            serial = result[0][0]

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger("Can't lookup serial number from database: %s" % (error.message,))
            raise PKIDBException(message="Can't lookup serial number from database: %s" % (error.message,))

        if result >= self._MAX_SERIAL_NUMBER:
            self.__logger.error("Maximal serial number of %u reached" % (self._MAX_SERIAL_NUMBER,))
            raise PKIDBException(message="Maximal serial number of %u reached" % (self._MAX_SERIAL_NUMBER,))

        else:
            self.__logger.info("Last serial number is %s" % (str(serial),))

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

        self.__logger.info("New serial number is %s" % (str(new_serial),))
        return new_serial

    def _store_extension(self, extlist):
        result = []

        self.__logger.info("Storing X509 extensions in database")

        for extension in extlist:
            # primary key is the sha512 hash of name+critical+data
            pkey = hashlib.sha512(extension[0] + str(extension[1]) + extension[2]).hexdigest()
            extdata = (pkey, extension[0], str(extension[1]), base64.b64encode(extension[2]))

            try:
                cursor = self.__db.cursor()
                cursor.execute("SELECT COUNT(hash) FROM extension WHERE hash='%s';" % (pkey,))
                searchresult = cursor.fetchall()

                # no entry found, insert data
                if searchresult[0][0] == 0:
                    cursor.execute("INSERT INTO extension (hash, name, critical, data) "
                                   "VALUES (?, ?, ?, ?);", extdata)

                cursor.close()
                self.__db.commit()
                result.append(pkey)
                self.__logger.info("X509 extension stored in 0x%s" % (pkey,))
            except sqlite3.Error as error:
                self.__db.rollback()
                self.__logger.error("Can't look for extension in database: %s" % (error.message,))
                raise PKIDBException(message="Can't look for extension in database: %s" % (error.message,))

        self.__logger.info("%u X509 extensions had been stored in the backend" % (len(extlist),))
        return result

    def _store_signature_algorithm_name(self, algoname):
        algo = algoname

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT id FROM signature_algorithm WHERE algorithm=?;", (algo,))
            result = cursor.fetchall()

            # no entry found?
            if len(result) == 0:
                cursor.execute("INSERT INTO signature_algorithm (algorithm) VALUES (?);", (algo,))
                cursor.execute("SELECT id FROM signature_algorithm WHERE algorithm=?;", (algo,))
                result = cursor.fetchall()
            algoid = result[0][0]

            self.__logger.info("X509 signature algorithm %s stored as %u in database" % (algo, algoid))

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't lookup signature algorithm in database: %s" % (error.message,))
            raise PKIDBException(message="Can't lookup signature algorithm in database: %s" % (error.message,))

        return algoid

    def _store_request(self, csr):
        self.__logger.info("Storing certificate signing request")

        # dump binary data of signing request
        csr_rawdata = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, csr)
        csr_pkey = hashlib.sha512(csr_rawdata).hexdigest()
        csr_data = {
            "pkey": csr_pkey,
            "request": base64.b64encode(csr_rawdata),
        }

        # check if csr already exists
        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT COUNT(hash) FROM signing_request WHERE hash='%s'" % (csr_pkey,))
            searchresult = cursor.fetchall()

            # no entry found, insert data
            if searchresult[0][0] == 0:
                cursor.execute("INSERT INTO signing_request (hash, request) "
                               "VALUES (?, ?);", (csr_data["pkey"], csr_data["request"]))

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't lookup signing request: %s" % (error.message,))
            raise PKIDBException(message="Can't lookup signing request: %s" % (error.message,))

        self.__logger.info("Certificate signing request stored as %s" % (csr_pkey,))
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
                    self.__logger.error("A certificate with serial number %s already exist\n" %
                                        (data["serial"],))
                    raise PKIDBException(message="A certificate with serial number %s already exist" %
                                                 (data["serial "],))

                # data will be replaced
                else:
                    # delete old dataset
                    self.__logger.info("Replacement flag set, deleting old certificate with serial number %s" %
                                       (str(data["serial"]),))
                    cursor.execute("DELETE FROM certificate WHERE serial_number=?;", (data["serial"],))

            cursor.execute("INSERT INTO certificate (serial_number, version, start_date, end_date, "
                           "subject, fingerprint_md5, fingerprint_sha1, certificate, state, issuer, "
                           "signature_algorithm_id, keysize) VALUES "
                           "(?, ?, ?, "
                           "?, ?, ?, ?, "
                           "?, ?, ?, ?, ?);",
                           (data["serial"], data["version"], data["start_date"], data["end_date"], data["subject"],
                            data["fp_md5"], data["fp_sha1"], data["pubkey"], data["state"], data["issuer"],
                            data["signature_algorithm_id"], data["keysize"]))

            if "csr" in data:
                self.__logger.info("Certificate signing request found, linking certificate with serial "
                                   "number %s to signing request 0x%s" % (str(data["serial"]), data["csr"]))
                cursor.execute("UPDATE certificate SET signing_request==? WHERE serial_number=?;",
                               (data["csr"], data["serial"]))

            if "revreason" in data:
                self.__logger.info("Revocation flag found, set revocation reason to %s with revocation time "
                                   "%s for certificate with serial number %s" % (str(data["revreason"]),
                                                                                 data["revtime"], data["serial"]))
                cursor.execute("UPDATE certificate SET revocation_reason=?, "
                               "revocation_date=?, state=? WHERE "
                               "serial_number=?;", (data["revreason"], data["revtime"], data["state"],
                                                    data["serial"]))

            if "extension" in data:
                self.__logger.info("X509 extensions found, storing extensions in database")
                extkeys = self._store_extension(data["extension"])
                if extkeys:
                    # SQLite doesn't support array, convert array to comma separated string instead
                    data["extkey"] = ','.join(extkeys)
                    cursor.execute("UPDATE certificate SET extension=? WHERE serial_number=?;",
                                   (data["extkey"], data["serial"]))
                    for ekey in extkeys:
                        self.__logger.info("Linking X509 extension 0x%s to certificate with serial number 0x%s"
                                           % (ekey, data["serial"]))
            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't update certificate data in database: %s" % (error.message,))
            raise PKIDBException(message="Can't update certificate data in database: %s" % (error.message,))

    def housekeeping(self, autorenew=True, validity_period=None, cakey=None):
        self.__logger.info("Running housekeeping")

        try:
            cursor = self.__db.cursor()

            qdata = {
                "valid": self._certificate_status_map["valid"],
                "invalid": self._certificate_status_map["invalid"],
                "expired": self._certificate_status_map["expired"],
                "now": time.time(),
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
                               "auto_renewable=True AND state=?;", (qdata["valid"],))

                result = cursor.fetchall()
                self.__logger.info("Found %u certificates eligible for auto renewal" % (len(result),))

                if len(result) > 0:
                    for sn in result:
                        new_start = self._unix_timestamp_to_asn1_time(time.time())
                        if validity_period:
                            self.__logger.info("Using new validity period of %f sec instead of %f sec for renewal"
                                               % (86400. * validity_period, sn[1]))
                            new_end = self._unix_timestamp_to_asn1_time(time.time() + 86400. * validity_period)
                        else:
                            self.__logger.info("Using validity period of %f sec for renewal" % (sn[1],))
                            new_end = self._unix_timestamp_to_asn1_time(time.time() + sn[1])

                        self.__logger.info("Renewing certificate with serial number %s (notBefore=%s, "
                                           "notAfter=%s)" % (str(sn[0]), new_start, new_end))
                        self.renew_certificate(sn[0], new_start, new_end, cakey)

            # set all invalid certificates to valid if notBefore < now and notAfter > now
            self.__logger.info("Set all invalid certificates to valid if notBefore < now and notAfter > now")
            cursor.execute("SELECT serial_number, start_date, end_date FROM certificate WHERE state=? AND "
                           "(start_date < ?) AND (end_date > ?);",
                           (qdata["invalid"], qdata["now"], qdata["now"]))
            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from invalid to valid" % (len(result),))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number %s changed from invalid to valid because "
                                       "(%f < %f) AND (%f > %f)" % (str(res[0]), res[1], qdata["now"], res[2],
                                                                    qdata["now"]))

            cursor.execute("UPDATE certificate SET state=? WHERE state=? AND "
                           "(start_date < ?) AND (end_date > ?);",
                           (qdata["valid"], qdata["invalid"], qdata["now"], qdata["now"]))

            # set all valid certificates to invalid if notBefore >= now
            self.__logger.info("Set all valid certificates to invalid if notBefore >= now")
            cursor.execute("SELECT serial_number, start_date FROM certificate WHERE state=? AND "
                           "(start_date >= ?);", (qdata["valid"], qdata["now"]))
            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from valid to invalid" % (len(result),))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number %s changed from valid to invalid because "
                                       "(%f >= %f)" % (str(res[0]), res[1], qdata["now"]))

            cursor.execute("UPDATE certificate SET state=? WHERE state=? AND "
                           "(start_date >= ?);", (qdata["invalid"], qdata["valid"], qdata["now"]))

            # set all valid certificates to expired if notAfter <= now
            self.__logger.info("Set all valid certificates to expired if notAfter <= now")
            cursor.execute("SELECT serial_number, end_date FROM certificate WHERE state=? AND "
                           "(end_date <= ?);", (qdata["valid"], qdata["now"]))
            result = cursor.fetchall()
            self.__logger.info("%u certificates will be set from valid to expired" % (len(result),))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Certificate with serial number %s changed from valid to expired because "
                                       "(%f <= %f)" % (str(res[0]), res[1], qdata["now"]))

            cursor.execute("UPDATE certificate SET state=? WHERE state=? AND "
                           "(end_date <= ?);", (qdata["expired"], qdata["valid"], qdata["now"]))

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't validate certificates: %s" % (error.message,))
            raise PKIDBException(message="Can't validate certificates: %s\n" % (error.message,))

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
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't read certifcate informations from database:%s" % (error.message,))
            raise PKIDBException(message="Can't read certifcate informations from database:%s" % (error.message,))

        statistics["state"] = state_statistics
        statistics["keysize"] = keysize_statistics
        statistics["signature_algorithm"] = signature_algorithm_statistics
        statistics["revoked"] = revocation_statistics

        for stat_type in statistics:
            for key in statistics[stat_type]:
                self.__logger.info("%s:%s:%u" % (stat_type, key, statistics[stat_type][key]))

        return statistics

    def _insert_empty_cert_data(self, serial, subject):
        self.__logger.info("Inserting temporary certificate data for serial number %s and subject %s"
                           % (str(serial), subject))

        try:
            cursor = self.__db.cursor()

            # insert empty data to "register" serial number until the
            # signed certificate can be committed
            dummy_data = {
                "serial": serial,
                "subject": subject,
                "state": self._certificate_status_map["temporary"],
            }
            cursor.execute("INSERT INTO certificate (serial_number, subject, state) VALUES "
                           "(?, ?, ?);", (dummy_data["serial"], dummy_data["subject"], dummy_data["state"]))

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't insert new serial number into database: %s" % (error.message,))
            raise PKIDBException(message="Can't insert new serial number into database: %s" % (error.message,))

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
        self.__logger.info("Removing certificate")

        try:
            cursor = self.__db.cursor()
            cursor.execute("DELETE FROM certificate WHERE serial_number=?;", (serial,))

            self.__logger.info("Certificate with serial number %s has been removed from the database" % (str(serial),))

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't remove certificate from database: %s" % (error.message,))
            raise PKIDBException(message="Can't remove certificate from database: %s" % (error.message,))

        return None

    def generate_revocation_list(self):
        self.__logger.info("Generating certificate revocation list")

        crl = OpenSSL.crypto.CRL()

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number, revocation_reason, revocation_date "
                           "FROM certificate WHERE state=%d" % (self._certificate_status_map["revoked"]))

            result = cursor.fetchall()
            self.__logger.info("%u revoked certificates found in database" % (len(result),))

            for revoked in result:
                revcert = OpenSSL.crypto.Revoked()
                revcert.set_serial("%x" % (revoked[0],))
                revcert.set_reason(self._revocation_reason_reverse_map[revoked[1]])
                revcert.set_rev_date(self._unix_timestamp_to_asn1_time(revoked[2]))

                crl.add_revoked(revcert)
                self.__logger.info("Certificate with serial number %s added to revocation list with "
                                   "revocation reason %s and revocation date %s" %
                                   (str(revoked[0]), self._revocation_reason_reverse_map[revoked[1]],
                                    self._unix_timestamp_to_asn1_time(revoked[2])))

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't fetch revoked certificates from backend: %s" % (error.message,))
            raise PKIDBException(message="Can't fetch revoked certificates from backend: %s" % (error.message,))
        except OpenSSL.crypto.Error as x509error:
            self.__db.rollback()
            self.__logger.error("Can't build revocation list: %s" % (x509error.message,))
            raise PKIDBException(message="Can't build revocation list: %s" % (x509error.message,))

        return crl

    def revoke_certificate(self, serial, reason, revocation_date, force=False):
        try:
            qdata = {
                "serial": serial,
                "reason": self._revocation_reason_map[reason],
                "date": revocation_date,
                "state": self._certificate_status_map["revoked"],
            }

            cursor = self.__db.cursor()

            if force:
                cursor.execute("SELECT 1 FROM certificate WHERE serial_number=%(serial)s;", qdata)
                result = cursor.fetchall()
                if len(result) == 0:
                    qdata["version"] = 2
                    qdata["subject"] = "Placeholder, set by revoking non-existent certificate with serial number %s " \
                                       "and using the force flag." % (serial,)
                    qdata["certificate"] = qdata["subject"]

                    cursor.execute("INSERT INTO certificate (serial_number, version, subject, certificate, state) "
                                   "VALUES (%(serial)s, %(version)s, %(subject)s, %(certificate)s, %(state)s);", qdata)

            self.__logger.info("Revoking certificate with serial number %s with revocation reason %s "
                               "and revocation date %s" % (str(serial), reason, revocation_date))

            cursor.execute("UPDATE certificate SET state=?, revocation_date=?, "
                           "revocation_reason=? WHERE serial_number=?;", (qdata["state"], qdata["date"],
                                                                          qdata["reason"], qdata["serial"]))
            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't update certifcate in backend: %s" % (error.message,))
            raise PKIDBException(message="Can't update certifcate in backend: %s" % (error.message,))

        return None

    def get_certificate(self, serial):

        qdata = {
            "serial": serial,
        }

        self.__logger.info("Getting ASN1 data for certificate with serial number 0x%s" % (serial,))

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT certificate FROM certificate WHERE serial_number=?;", (qdata["serial"],))
            result = cursor.fetchall()
            cursor.close()
            self.__db.commit()

            if len(result) == 0:
                return None
            else:
                try:
                    if result[0][0]:
                        asn1_data = base64.b64decode(result[0][0])
                        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, asn1_data)
                    else:
                        return None

                except OpenSSL.crypto.Error as error:
                    self.__db.rollback()
                    self.__logger.error("Can't parse ASN1 data: %s" % (error.message,))
                    raise PKIDBException(message="Can't parse ASN1 data: %s" % (error.message,))
        except sqlite3.Error as error:
            self.__logger.error("Can't read certificate data from database: %s" % (error.message,))
            raise PKIDBException(message="Can't read certificate data from database: %s" % (error.message,))

        return cert

    def dump_database(self):
        self.__logger.info("Dumping backend database")
        dump = {}

        try:
            cursor = self.__db.cursor()
            self.__logger.info("Dumping certificate table")

            # dumping certificates
            certdump = []
            cursor.execute("SELECT serial_number, version, start_date, "
                           "end_date, subject, auto_renewable, "
                           "auto_renew_start_period, "
                           "auto_renew_validity_period, issuer, keysize, fingerprint_md5, "
                           "fingerprint_sha1, certificate, signature_algorithm_id, extension, signing_request, "
                           "state, revocation_date, revocation_reason FROM certificate;")
            result = cursor.fetchall()
            self.__logger.info("Dumping %u certificates" % (len(result),))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Dumping certificate with serial number %s" % (str(res[0]),))
                    # check if extension row is not empty
                    if res[14]:
                        entry = {
                            "serial_number": str(res[0]),
                            "version": res[1],
                            "start_date": res[2],
                            "end_date": res[3],
                            "subject": res[4],
                            "auto_renewable": res[5],
                            "auto_renew_start_period": res[6],
                            "auto_renew_validity_period": res[7],
                            "issuer": res[8],
                            "keysize": res[9],
                            "fingerprint_md5": res[10],
                            "fingerprint_sha1": res[11],
                            "certificate": res[12],
                            "signature_algorithm_id": res[13],

                            # split comma separated string of extensions into an array
                            "extension": res[14].split(","),

                            "signing_request": res[15],
                            "state": res[16],
                            "revocation_date": res[17],
                            "revocation_reason": res[18],
                        }
                    else:
                        entry = {
                            "serial_number": str(res[0]),
                            "version": res[1],
                            "start_date": res[2],
                            "end_date": res[3],
                            "subject": res[4],
                            "auto_renewable": res[5],
                            "auto_renew_start_period": res[6],
                            "auto_renew_validity_period": res[7],
                            "issuer": res[8],
                            "keysize": res[9],
                            "fingerprint_md5": res[10],
                            "fingerprint_sha1": res[11],
                            "certificate": res[12],
                            "signature_algorithm_id": res[13],
                            "extension": res[14],
                            "signing_request": res[15],
                            "state": res[16],
                            "revocation_date": res[17],
                            "revocation_reason": res[18],
                        }

                    # convert "boolean" from SQLite into REAL booleans
                    if entry["auto_renewable"] == 0:
                        entry["auto_renewable"] = False
                    elif entry["auto_renewable"] == 1:
                        entry["auto_renewable"] = True

                    certdump.append(entry)
            dump["certificate"] = certdump

            # dumping x509 extensions
            extdump = []
            cursor.execute("SELECT hash, name, critical, data FROM extension;")
            result = cursor.fetchall()
            self.__logger.info("Dumping %u extensions" % (len(result),))
            if len(result) > 0:
                for res in result:
                    self.__logger.info("Dumping extension with key id %s" % (res[0],))
                    entry = {
                        "hash": res[0],
                        "name": res[1],
                        "critical": res[2],
                        "data": res[3],
                    }

                    # convert "boolean" from SQLite into REAL booleans
                    if entry["critical"] == 0:
                        entry["critical"] = False
                    elif entry["critical"] == 1:
                        entry["critical"] = True

                    extdump.append(entry)
            dump["extension"] = extdump

            # dumping signature algorithms
            self.__logger.info("Dumping list of signature algorithms")

            algodump = []
            cursor.execute("SELECT id, algorithm FROM signature_algorithm;")
            result = cursor.fetchall()
            self.__logger.info("Dumping %u signature algorithms" % (len(result),))

            if len(result) > 0:
                for res in result:
                    self.__logger.info("Dumping signing algorithm %s with id %u" % (res[1], res[0]))
                    entry = {
                        "id": str(res[0]),
                        "algorithm": res[1],
                    }
                    algodump.append(entry)
            dump["signature_algorithm"] = algodump

            # dumping certificate signing requests
            csrdump = []
            cursor.execute("SELECT hash, request FROM signing_request;")
            result = cursor.fetchall()

            self.__logger.info("Dumping %u certificate signing requests" % (len(result),))
            if len(result) > 0:
                for res in result:
                    self.__logger.info("Dumping signing request %s" % (res[0],))
                    entry = {
                        "hash": res[0],
                        "request": res[1],
                    }
                    csrdump.append(entry)

            dump["signing_request"] = csrdump

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't read from backend database: %s" % (error.message,))
            raise PKIDBException(message="Can't read from backend database: %s" % (error.message,))

        return dump

    def list_serial_number_by_state(self, state):
        sn_list = []

        if state:
            qdata = {
                "state": self._certificate_status_map[state],
            }

            self.__logger.info("Getting serial numbers for certificates with state %u" % (qdata["state"],))
            try:
                cursor = self.__db.cursor()
                cursor.execute("SELECT serial_number FROM certificate WHERE state=?;", (qdata["state"],))

                result = cursor.fetchall()
                for res in result:
                    self.__logger.info("Adding serial number %s to result list" % (str(res[0]),))
                    sn_list.append(str(res[0]))

                cursor.close()
                self.__db.commit()
            except sqlite3.Error as error:
                self.__db.rollback()
                self.__logger.error("Can't get list of serial numbers: %s" % (error.message,))
                raise PKIDBException(message="Can't get list of serial numbers: %s" % (error.message,))

        else:
            self.__logger.info("Getting all serial numbers")
            try:
                cursor = self.__db.cursor()
                cursor.execute("SELECT serial_number FROM certificate;")

                result = cursor.fetchall()
                for res in result:
                    self.__logger.info("Adding serial number %s to result list" % (str(res[0]),))
                    sn_list.append(str(res[0]))

                cursor.close()
                self.__db.commit()
            except sqlite3.Error as error:
                self.__db.rollback()
                self.__logger.error("Can't get list of serial numbers: %s" % (error.message,))
                raise PKIDBException(message="Can't get list of serial numbers: %s" % (error.message,))

        return sn_list

    def restore_database(self, dump):
        try:
            cursor = self.__db.cursor()
            # restore certificate table
            self.__logger.info("Restoring certificate table")
            for cert in dump["certificate"]:
                # SQLite3 can't handle arrays so we create a commma separated string from the array
                if cert["extension"]:
                    cert["extension"] = ",".join(cert["extension"])

                cursor.execute("INSERT INTO certificate (serial_number, version, start_date, "
                               "end_date, subject, auto_renewable, "
                               "auto_renew_start_period, "
                               "auto_renew_validity_period, issuer, keysize, fingerprint_md5, "
                               "fingerprint_sha1, certificate, signature_algorithm_id, extension, signing_request, "
                               "state, revocation_date, revocation_reason) "
                               "VALUES(?, ?, ?, "
                               "?, ?, ?, "
                               "?, "
                               "?, ?, ?, "
                               "?, ?, ?, "
                               "?, ?, ?, "
                               "?, ?, ?);",
                               (cert["serial_number"], cert["version"], cert["start_date"], cert["end_date"],
                                cert["subject"], cert["auto_renewable"], cert["auto_renew_start_period"],
                                cert["auto_renew_validity_period"], cert["issuer"], cert["keysize"],
                                cert["fingerprint_md5"], cert["fingerprint_sha1"], cert["certificate"],
                                cert["signature_algorithm_id"], cert["extension"], cert["signing_request"],
                                cert["state"], cert["revocation_date"], cert["revocation_reason"]))

            self.__logger.info("%u rows restored for certificate table" % (len(dump["certificate"]),))
            self.__logger.info("Forcing reindexing on certificate table")
            cursor.execute("REINDEX certificate;")

            # restore extension table
            self.__logger.info("Restoring extension table")
            for ext in dump["extension"]:
                cursor.execute("INSERT INTO extension (hash, name, critical, data) VALUES "
                               "(?, ?, ?, ?);", (ext["hash"], ext["name"], ext["critical"], ext["data"]))
            self.__logger.info("%u rows restored for extension table" % (len(dump["extension"]),))
            self.__logger.info("Forcing reindexing on table extension")
            cursor.execute("REINDEX extension;")

            # restore signing_request table
            self.__logger.info("Restoring signing_request table")
            for csr in dump["signing_request"]:
                cursor.execute("INSERT INTO signing_request (hash, request) VALUES "
                               "(?, ?);", (csr["hash"], csr["request"]))
            self.__logger.info("%u rows restored for signing_request table" % (len(dump["signing_request"]),))

            self.__logger.info("Forcing reindexing on table signing_request")
            cursor.execute("REINDEX signing_request;")

            # restore signature_algorithm
            self.__logger.info("Restoring signature_algorithm table")
            for sigalgo in dump["signature_algorithm"]:
                cursor.execute("INSERT INTO signature_algorithm (id, algorithm) "
                               "VALUES (?, ?);", (sigalgo["id"], sigalgo["algorithm"]))
            self.__logger.info("%u rows restored for signature_algorithm table" % (len(dump["signature_algorithm"]),))

            # fetch last sequence number
            cursor.execute("SELECT id FROM signature_algorithm ORDER BY id DESC LIMIT 1;")
            result = cursor.fetchall()
            # if table is empty start at 1
            if len(result) == 0:
                newsequence = 1
            else:
                newsequence = long(result[0][0]) + 1

            self.__logger.info("Readjusting primary key counter to %u" % (newsequence,))
            cursor.execute("UPDATE sqlite_sequence SET seq=%u WHERE name='signature_algorithm';" % (newsequence,))
            self.__logger.info("Forcing reindexing on table signature_algorithm")
            cursor.execute("REINDEX signature_algorithm;")

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't restore database from dump: %s" % (error.message,))
            raise PKIDBException(message="Can't restore database from dump: %s" % (error.message,))

        return True

    def get_certificate_data(self, serial):
        qdata = {"serial": serial, }

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
                           "WHERE serial_number=?;", (qdata["serial"],))
            result = cursor.fetchall()
            if len(result) > 0:
                data = {
                    "serial_number": "%u (0x%02x)" % (long(result[0][0]), long(result[0][0])),
                    "start_date": time.strftime("%a, %d %b %Y %H:%M:%S %z", time.localtime(result[0][2])),
                    "end_date": time.strftime("%a, %d %b %Y %H:%M:%S %z", time.localtime(result[0][3])),
                    "subject": result[0][4],
                    "auto_renewable": result[0][5],
                    "issuer": result[0][8],
                    "keysize": result[0][9],
                    "fingerprint_md5": result[0][10],
                    "fingerprint_sha1": result[0][11],
                    "certificate": result[0][12],
                    "algorithm": result[0][13],
                    "extension": result[0][14],
                    "signing_request": result[0][15],
                    "state": self._certificate_status_reverse_map[result[0][16]],
                }
                # check if version is NULL (e.g. it is a dummy)
                if result[0][1]:
                    data["version"] = result[0][1] + 1
                else:
                    data["version"] = -1

                if not data["keysize"]:
                    data["keysize"] = -1

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
                    cursor.execute("SELECT request FROM signing_request WHERE hash=?;", (data["signing_request"],))
                    csr_result = cursor.fetchall()
                    data["signing_request"] = csr_result[0][0]

                if data["extension"]:
                    extlist = []
                    # convert comma separated list to an array
                    data["extension"] = data["extension"].split(",")
                    for ext in data["extension"]:
                        qext = {"hash": ext, }
                        cursor.execute("SELECT name, critical, data FROM extension WHERE hash=?;", (qext["hash"],))
                        ext_result = cursor.fetchall()
                        extlist.append({
                            "name": ext_result[0][0],
                            "critical": ext_result[0][1],
                            "data": ext_result[0][2]
                        })
                    data["extension"] = extlist
                else:
                    data["extension"] = []
            else:
                data = None

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't lookup certificate with serial number %s in database: %s"
                                % (serial, error.message))
            raise PKIDBException(message="Can't lookup certificate with serial number %s in database: %s"
                                         % (serial, error.message))

        return data

    # FIXME: Eligible for move to parent class
    def _get_from_config_global(self, option):
        if option in self.__config["global"]:
            return self.__config["global"][option]
        else:
            return None

    def set_certificate_metadata(self, serial, auto_renew=None, auto_renew_start_period=None,
                                 auto_renew_validity_period=None):

        if auto_renew is None and not auto_renew_start_period and not auto_renew_validity_period:
            return False

        if not self.get_certificate(serial):
            return None

        try:
            cursor = self.__db.cursor()

            qdata = {
                "serial": serial,
                "auto_renewable": auto_renew,
                "auto_renew_start_period": auto_renew_start_period,
                "auto_renew_validity_period": auto_renew_validity_period,
            }

            if auto_renew is None:
                # setting auto_renew_start_period or auto_renew_validity_period implicitly sets the auto_renew flag
                if auto_renew_start_period or auto_renew_validity_period:
                    qdata["auto_renewable"] = True
                    auto_renew = True

                if auto_renew_start_period:
                    qdata["auto_renew_start_period"] = float(qdata["auto_renew_start_period"]) * 86400.
                    cursor.execute("UPDATE certificate SET "
                                   "auto_renew_start_period=?, "
                                   "auto_renewable=? WHERE serial_number=?;",
                                   (qdata["auto_renew_start_period"], qdata["auto_renewable"], qdata["serial"]))

                    self.__logger.info("Setting auto_renew_start_period of certificate %s to %f days." %
                                       (str(serial), qdata["auto_renew_start_period"] / 86400.))
                    udata = {
                        "serial": serial,
                    }
                    # set auto_renew_validity_period to validity_period of not set
                    if not auto_renew_validity_period:
                        udata["auto_renew_validity_period"] = float(self._get_from_config_global("validity_period")) \
                                                              * 86400
                        cursor.execute("UPDATE certificate SET "
                                       "auto_renew_validity_period=? "
                                       "WHERE serial_number=? AND auto_renew_validity_period IS NULL;",
                                       (udata["auto_renew_validity_period"], udata["serial"]))
                        self.__logger.info("Setting auto_renew_validity_period to %f days if not already set." %
                                           (udata["auto_renew_validity_period"] / 86400.,))

                if auto_renew_validity_period:
                    qdata["auto_renew_validity_period"] = float(qdata["auto_renew_validity_period"]) * 86400.
                    cursor.execute("UPDATE certificate SET "
                                   "auto_renew_validity_period=?, "
                                   "auto_renewable=? WHERE serial_number=?;",
                                   (qdata["auto_renew_validity_period"], qdata["auto_renewable"], qdata["serial"]))

                    self.__logger.info("Setting auto_renew_validity_period of certificate %s to %f days." %
                                       (str(serial), qdata["auto_renew_validity_period"] / 86400.))

                    udata = {
                        "serial": serial,
                    }
                    # set auto_renew_start_period to validity_period of not set
                    if not auto_renew_start_period:
                        udata["auto_renew_start_period"] = float(
                            self._get_from_config_global("auto_renew_start_period")) \
                                                           * 86400.
                        cursor.execute("UPDATE certificate SET "
                                       "auto_renew_start_period=? "
                                       "WHERE serial_number=? AND auto_renew_start_period IS NULL;",
                                       (udata["auto_renew_start_period"], udata["serial"]))
                        self.__logger.info("Setting auto_renew_start_period to %f days if not already set." %
                                           (udata["auto_renew_start_period"] / 86400.,))

            if auto_renew:
                # setting auto_renewable flag also sets auto_renew_start_period and auto_renew_validity_period
                if not auto_renew_start_period:
                    auto_renew_start_period = float(self._get_from_config_global("auto_renew_start_period")) * 86400.
                    self.__logger.info("Setting auto_renew_start_period from configuration file to %s" %
                                       (auto_renew_start_period,))

                    if not auto_renew_start_period:
                        cursor.close()
                        self.__db.rollback()
                        self.__logger.error("Can't lookup option auto_renew_start_period from configuration file.")
                        raise PKIDBException(message="Error: Can't lookup option auto_renew_start_period "
                                                     "from configuration file.")

                    qdata["auto_renew_start_period"] = auto_renew_start_period

                if not auto_renew_validity_period:
                    auto_renew_validity_period = float(self._get_from_config_global("validity_period")) * 86400.
                    self.__logger.info("Setting auto_renew_validity_period from configuration file to %s" %
                                       (auto_renew_validity_period,))

                    if not auto_renew_validity_period:
                        cursor.close()
                        self.__db.rollback()
                        self.__logger.error("Can't lookup validity_period from configuration file.")
                        raise PKIDBException(message="Can't lookup validity_period from configuration file.")

                    qdata["auto_renew_validity_period"] = auto_renew_validity_period

                cursor.execute("UPDATE certificate SET auto_renewable=?, "
                               "auto_renew_start_period=?, "
                               "auto_renew_validity_period=? "
                               "WHERE serial_number=?;",
                               (qdata["auto_renewable"], qdata["auto_renew_start_period"] / 86400.,
                                qdata["auto_renew_validity_period"] / 86400., qdata["serial"]))

                self.__logger.info("Setting auto_renewable to %s (auto_renew_start_period is %s days and "
                                   "auto_renew_validity_period is %s days)" %
                                   (qdata["auto_renewable"], qdata["auto_renew_start_period"] / 86400.,
                                    qdata["auto_renew_validity_period"] / 86400.))

            # explicitly check for False to avoid None
            elif not auto_renew:
                # disabling auto_renew flag also removes auto_renew_start_period and auto_renew_validity_period
                qdata["auto_renew_start_period"] = None
                qdata["auto_renew_validity_period"] = None
                cursor.execute("UPDATE certificate SET auto_renewable=?, "
                               "auto_renew_start_period=NULL, auto_renew_validity_period=NULL "
                               "WHERE serial_number=?;", (qdata["auto_renewable"], qdata["serial"]))
            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't update auto_renew parameters: %s" % (error.message,))
            sys.stderr.write("Error: Can't update auto_renew parameters: %s\n" % (error.message,))

        return True

    def _get_signature_algorithm(self, algo_id):
        qdata = {"id": algo_id, }

        try:
            cursor = self.__db.cursor()
            cursor.execute("SELECT algorithm FROM signature_algorithm WHERE id=?;", (qdata["id"],))
            result = cursor.fetchall()
            if len(result) == 0:
                algo = None
            else:
                algo = result[0][0]

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't lookup algorithm id %u in database: %s" % (algo_id, error.message))
            raise PKIDBException(message="Can't lookup algorithm id %u in database: %s" % (algo_id, error.message))

        return algo

    def _get_meta_data(self, serial, fields=None):
        result = {
            "auto_renewable": None,
            "auto_renew_start_period": None,
            "auto_renew_validity_period": None,
            "state": None,
            "revocation_date": None,
            "revocation_reason": None,
            "certificate": None,
            "signing_request": None,
        }
        self.__logger.info("Fetching metadata for certificate with serial number %s from database." % (serial,))

        try:
            qdata = {"serial": serial, }
            cursor = self.__db.cursor()
            cursor.execute("SELECT auto_renewable, extract(EPOCH FROM auto_renew_start_period), "
                           "extract(EPOCH FROM auto_renew_validity_period), state, "
                           "extract(EPOCH FROM revocation_date), revocation_reason, certificate, signing_request "
                           "FROM certificate WHERE serial_number=?;", (qdata["serial"],))
            qresult = cursor.fetchall()
            cursor.close()
            self.__db.commit()

            if len(qresult) != 0:
                result["auto_renewable"] = qresult[0][0]
                result["auto_renew_start_period"] = qresult[0][1]
                result["auto_renew_validity_period"] = qresult[0][2]
                result["state"] = qresult[0][3]
                result["revocation_date"] = qresult[0][4]
                result["revocation_reason"] = qresult[0][5]
                result["certificate"] = qresult[0][6]
                result["signing_request"] = qresult[0][7]
        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't fetch metadata from backend: %s" % (error.message,))
            raise PKIDBException(message="Can't fetch metadata from backend: %s" % (error.message,))

        if not fields:
            return result
        elif len(fields) == 0:
            return result
        else:
            returnval = {}
            for request in fields:
                if request in result:
                    returnval[request] = result[request]
                else:
                    returnval[request] = None
                    self.__logger.warning("Skipping unknown meta data field %s for certificate with serial number %s"
                                          % (request, serial))
            return returnval

    def _set_meta_data(self, serial, metadata):
        # discard empty requests
        if not metadata:
            return None

        if len(metadata.keys()) == 0:
            return None

        try:
            cursor = self.__db.cursor()
            data = metadata
            # add serial number to array
            data["serial"] = serial

            for meta in metadata:
                if meta != "serial":
                    if meta in self._metadata:
                        query = "UPDATE certificate SET %s=? WHERE serial_number=?;" % (meta,)
                        self.__logger.info("Setting %s to %s for serial number %s" % (meta, metadata[meta], serial))

                        cursor.execute(query, (data[meta], data["serial"]))
                    else:
                        self.__logger.warning("Unknown meta data field %s for certificate with serial number %s"
                                              % (meta, serial))

            cursor.close()
            self.__db.commit()
        except sqlite3.Error as error:
            self.__logger.error("Failed to set meta data in database: %s" % (error.message,))
            self.__db.rollback()

        return None

    def search_certificate(self, searchstring):
        serials = []
        try:
            query = {"search": searchstring, }
            cursor = self.__db.cursor()
            cursor.execute("SELECT serial_number FROM certificate WHERE subject LIKE ?;", (query["search"],))
            result = cursor.fetchall()
            cursor.close()
            self.__db.commit()

            for serial in result:
                serials.append(serial[0])

        except sqlite3.Error as error:
            self.__db.rollback()
            self.__logger.error("Can't search subject in database: %s" % (error.message,))
            raise PKIDBException(message="Can't search subject in database: %s" % (error.message,))

        return serials
