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
import sys
import time
import re
import OpenSSL

__all__ = ["pgsql", "sqlite", "mysql"]


class PKIDBException(Exception):
    message = None

    def __init__(self, *args, **kwargs):
        super(PKIDBException, self).__init__(args, kwargs)
        if "message" in kwargs:
            self.message = kwargs["message"]
        else:
            self.message = ""

    def __str__(self):
        super(PKIDBException, self).__str__()
        return self.message


class Backend(object):
    # Note: RFC 3280 (4.1.2.2  Serial number) states the serial number
    # must be:
    #  * unique
    #  * non-negative integer
    #  * up to 20 octets (up to 2**160)
    #  * not longer than 20 octets
    _MAX_SERIAL_NUMBER = 0x7fffffffffffffff

    _certificate_status_reverse_map = {
        -1: "temporary",
        0: "pending",
        1: "valid",
        2: "revoked",
        3: "expired",
        4: "invalid",
        5: "dummy",
    }

    _certificate_status_map = {
        "temporary": -1,
        "pending": 0,
        "valid": 1,
        "revoked": 2,
        "expired": 3,
        "invalid": 4,
        "dummy": 5,
    }

    _revocation_reason_map = {
        "unspecified": 0,
        "keycompromise": 1,
        "cacompromise": 2,
        "affiliationchanged": 3,
        "superseded": 4,
        "cessationofoperation": 5,
        "certificatehold": 6,
        "unspecified (not used as defined in RFC5280)": 7,
        "removefromcrl": 8,
        "privilegewithdrawn": 9,
        "aacompromise": 10,
    }

    _revocation_reason_reverse_map = {
        0: "unspecified",
        1: "keycompromise",
        2: "cacompromise",
        3: "affiliationchanged",
        4: "superseded",
        5: "cessationofoperation",
        6: "certificatehold",
        7: "unspecified (not used as defined in RFC5280)",
        8: "removefromcrl",
        9: "privilegewithdrawn",
        10: "aacompromise",
    }

    _keyusage_list = [
        "digitalsignature",
        "nonrepudiation",
        "keyencipherment",
        "dataencipherment",
        "keyagreement",
        "keycertsign",
        "crlsign",
        "encipheronly",
        "decipheronly",
    ]

    _extended_keyusage_list = [
        "serverauth",
        "clientauth",
        "codesigning",
        "emailprotection",
        "timestamping",
        "mscodeind",
        "mscodecom",
        "msctlsign",
        "mssgc",
        "msefs",
        "nssgc",
    ]

    # known meta data fields
    _metadata = ["auto_renewable",
                 "auto_renew_start_period",
                 "auto_renew_validity_period",
                 "state",
                 "revocation_date",
                 "revocation_reason",
                 "certificate",
                 "signing_request",
                 "start_date",
                 "end_date",
                 "signature_algorithm_id",
                 ]

    __logger = None

    @staticmethod
    def _get_loglevel(string):
        """
        Returns value of loglevel for logging from string
        :param string: string
        :return: numeric loglevel
        """
        if string.lower() == "debug":
            return logging.DEBUG
        elif string.lower() == "info":
            return logging.INFO
        elif string.lower() == "warning":
            return logging.WARNING
        elif string.lower() == "warn":
            return logging.WARN
        elif string.lower() == "error":
            return logging.ERROR
        elif string.lower() == "critical":
            return logging.CRITICAL
        else:
            sys.stderr.write("Error: Unknown log level %s\n" % (string,))
            raise PKIDBException(message="Unknown log level %s" % (string,))

    def __init_logger(self, options):
        """
        Setup logging based on the configuration setting
        :param options: parsed config file
        :return: None
        """
        name = os.path.basename(sys.argv[0])
        logformat = logging.Formatter(name + " %(name)s:%(lineno)d %(levelname)s: %(message)s")
        re_logging = re.compile("(\w+),(\w+):(.*)$")

        self.__logger = logging.getLogger("__init__")
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
                        handler.setLevel(logging.INFO)
                        handler.setFormatter(logformat)

                        self.__logger.addHandler(handler)
                    else:
                        sys.stderr.write("Error: Unknown logging mechanism %s\n" % (logtype,))
                        raise PKIDBException(message="Unknown logging mechanism %s" % (logtype,))
        else:
            # set default logging
            # initialize logging subsystem

            handler = logging.handlers.SysLogHandler(address='/dev/log')
            handler.setLevel(logging.INFO)
            handler.setFormatter(logformat)

            self.__logger.addHandler(handler)

    def __init__(self, config):
        """
        Constructor
        :param config: dictionary of parsed configuration options
        :return: Nothing
        """
        self.__config = config
        if not self.__logger:
            self.__init_logger(self.__config)

        pass

    def _set_state(self, serial, state):
        """
        Set certificate state in the backend database
        :param serial: serial number
        :param state: numeric value for state
        :return: previous stored state, None if an error occured
        """

    def set_state(self, serial, state):
        """
        Set certificate state in the backend database
        :param serial: serial number
        :param state: state as string
        :return: previous stored state, None if an error occured
        """
        if state in self._certificate_status_map:
            return self._set_state(serial, self._certificate_status_map[state])
        else:
            return None

    def _get_state(self, serial):
        """
        Returns the state of a certificate identified by serial number
        :param serial: serial number
        :return: state
        """

    def _is_expired(self, serial):
        """
        Check if a certificate is expired
        :param serial: serial number
        :return: True if certificate is expired.
                 False if certificate is expired.
                 None if certifcate can not be found.
        """
        state = self._get_state(serial)
        if state:
            if state == self._certificate_status_map["expired"]:
                return True
            else:
                return False
        else:
            return None

    def _is_valid(self, serial):
        """
        Check if a certificate is valid
        :param serial: serial number
        :return: True if certificate is valid.
                 False if certificate is valid.
                 None if certifcate can not be found.
        """
        state = self._get_state(serial)
        if state:
            if state == self._certificate_status_map["valid"]:
                return True
            else:
                return False
        else:
            return None

    def _is_revoked(self, serial):
        """
        Check if a certificate was been revoked
        :param serial: serial number
        :return: True if certificate has been revoked.
                 False if certificate has not been revoked.
                 None if certifcate can not be found.
        """
        state = self._get_state(serial)
        if state:
            if state == self._certificate_status_map["revoked"]:
                return True
            else:
                return False
        else:
            return None

    def _has_serial_number(self, serial):
        """
        Check the backend for serial number
        :param serial: serial number to check for
        :return: True - if serial number was found
                 False - if serial number was not found
                 None - on error
        """

    def has_serial_number(self, serial):
        """
        Check the backend for serial number
        :param serial: serial number to check for
        :return: True - if serial number was found
                 False - if serial number was not found
                 None - on error
        """
        return self._has_serial_number(serial)

    def _get_last_serial_number(self):
        """
        Returns the last serial number
        :return: Last serial number
        """

    def _get_new_serial_number(self, cert):
        """
        Generate a new serial number. To avoid clashes the serial number will be written to the backend.
        Stale data should be removed by the signal handler and/or by running the backendcheck handler.
        :param cert: X509 object of new certificate
        :return: serial number
        """

    def __del__(self):
        """
        Destructor, close database connection
        :return: Nothing
        """

    def store_certificate(self, cert, csr=None, revoked=None, replace=False, autorenew=None, validity_period=None):
        """
        Stores a certificate in the backend.
        :param cert: X509 object to store
        :param csr: Optional, X509Req object
        :param revoked: Tuple with revocation information (reason, revocationtime).
                        if not set to None it marks the certificate as revoked.
        :param replace: Replace existing certificate, default is False
        :param autorenew: dictionary with autorenew information if the certificate is an auto renewable certificate
        :param validity_period: validity period for automatically renewed certificates
        :return: None
        """

    @staticmethod
    def _format_subject(subject):
        """
        Returns the subject as string from the tuple obtained from X509.get_subject().get_components()
        :param subject: subject tuple
        :return: string
        """

        intermediate = []
        for pair in subject:
            intermediate.append('='.join(pair))

        # subject start with /
        result = '/' + '/'.join(intermediate)

        return result

    @staticmethod
    def _unix_timestamp_to_asn1_time(timestamp):
        """
        Converts UNIX timestamp to ASN1 GENERALIZEDTIME string
        :param timestamp: UNIX timestamp
        :return: ASN1 GENERALIZEDTIME string
        """

        asn1_time = time.strftime("%Y%m%d%H%M%S%z", time.localtime(timestamp))
        return asn1_time

    def unix_timestamp_to_asn1_time(self, timestamp):
        """
        Converts UNIX timestamp to ASN1 GENERALIZEDTIME string
        :param timestamp: UNIX timestamp
        :return: ASN1 GENERALIZEDTIME string
        """
        return self._unix_timestamp_to_asn1_time(timestamp)

    def _date_string_to_unix_timestamp(self, datestring):
        """
        Convert date string in format %a, %d %b %Y %H:%M:%S %z to UNIX epoch
        :param datestring: string
        :return: UNIX epoch
        """
        stamp = None

        # although time.strftime supports %z time.strptime does not
        # split string into date and timeoffset
        re_data_tz = re.compile("^([A-Za-z0-9, :]+) ([+-][0-9]{4})")
        if re_data_tz.match(datestring):
            (date, tz) = re_data_tz.match(datestring).groups()
            try:
                stamp = time.mktime(time.strptime(date, "%a, %d %b %Y %H:%M:%S"))
                tz = long(tz) / 100.00

                stamp += 3600.0 * tz
            except ValueError as error:
                self.__logger.error("Can't convert %s to UNIX timestamp: %s" % (datestring, error.message))
                raise PKIDBException(message="Can't convert %s to UNIX timestamp: %s" % (datestring, error.message))
        return stamp

    @staticmethod
    def _asn1_time_to_unix_timestamp(asn1_time):
        """
        Converts ASN1 GENERALIZEDTIME string to UNIX timestamp
        :param asn1_time: ASN1 GENERALIZEDTIME string
        :return: UNIX timestamp
        """

        timestamp = None

        # Format of ASN1 GENERALIZEDTIME is one of:
        # YYYYMMDDhhmmssZ
        # YYYYMMDDhhmmss+hhmm
        # YYYYMMDDhhmmss-hhmm
        re_asn1_with_z = re.compile("^\d{14}Z$")
        re_asn1_with_offset = re.compile("^(\d{14})[+|-](\d{4})$")

        if re_asn1_with_z.match(asn1_time):
            timestamp = time.mktime(time.strptime(asn1_time, "%Y%m%d%H%M%SZ"))
        elif re_asn1_with_offset.match(asn1_time):
            # although time.strftime supports %z time.strptime does not
            # split string into date and timeoffset
            date = re_asn1_with_offset.match(asn1_time).groups()[0]
            offset = re_asn1_with_offset.match(asn1_time).groups()[1]

            timestamp = time.mktime(time.strptime(date, "%Y%m%d%H%M%S"))
            timestamp += 3600.00 * float(offset) / 100.00

        return timestamp

    def get_certificate(self, serial):
        """
        Returns a X509 object of a certificate identified by serial number
        :param serial: serial number
        :return: X509 object of certificate
        """

    def _store_extension(self, extlist):
        """
        Stores list of X509 extensions into the backend.
        :param extlist: List of x509 extension data. X509 extension
        data is an array containing [<name>,<critical>,<data>]

        :return: Returns list of primary keys for <extlist> from
        the databasebackend. If extensions don't exist in the database
        they will be inserted.
        """

    def _store_request(self, csr):
        """
        Stores certificate signing request
        :param csr: base64 encoded X509 data of certificate signing request
        :return: primary key of csr
        """

    def _store_signature_algorithm_name(self, algoname):
        """
        Stores signature algorithm by its name
        :param algoname: algorithm name
        :return: primary key of signature algorithm in lookup table
        """

    def _store_signature_algorithm(self, cert):
        """
        Stores signature algorithm
        :param cert: X509 object
        :return: primary key of signature algorithm in lookup table
        """
        algo = "undefined"

        try:
            algo = cert.get_signature_algorithm()
        except ValueError as error:
            self.__logger.warning("Undefined signature algorithm in certificate data: %s" % (error.message,))

        algoid = self._store_signature_algorithm_name(algo)

        return algoid

    def _extract_data(self, cert, csr=None, revoked=None):
        """
        Extract dictionary of data from X509 object and optional
        X509Req object and revocation data
        :param cert: X509 object of certificate
        :param csr: X509Req object
        :param revoked: revocation information
        :return: dictionary of extracted data
        """

        # extract x509 data from object
        certificate = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)

        dataset = {
            "subject": self._format_subject(cert.get_subject().get_components()),
            "version": cert.get_version(),
            "start_date": self._asn1_time_to_unix_timestamp(cert.get_notBefore()),
            "end_date": self._asn1_time_to_unix_timestamp(cert.get_notAfter()),
            "serial": cert.get_serial_number(),
            "issuer": self._format_subject(cert.get_issuer().get_components()),
            "pubkey": base64.b64encode(certificate),
            "fp_md5": hashlib.md5(certificate).hexdigest(),
            "fp_sha1": hashlib.sha1(certificate).hexdigest(),
            "keysize": cert.get_pubkey().bits(),
            "signature_algorithm_id": self._store_signature_algorithm(cert),
        }

        # check expiration / validity
        if dataset["start_date"] > time.time():
            dataset["state"] = self._certificate_status_map["invalid"]
        elif dataset["end_date"] < time.time():
            dataset["state"] = self._certificate_status_map["expired"]
        else:
            dataset["state"] = self._certificate_status_map["valid"]

        if csr:
            dataset["csr"] = self._store_request(csr)

        if revoked:
            dataset["revreason"] = revoked[0]
            dataset["revtime"] = revoked[1]
            dataset["state"] = 2

        # check for and extract X509 SSL extensions
        if cert.get_extension_count() > 0:
            x509ext = []
            for i in range(cert.get_extension_count()):
                extension = cert.get_extension(i)
                name = extension.get_short_name()
                criticality = extension.get_critical()
                data = extension.get_data()

                x509ext.append((name, criticality, data))
            dataset["extension"] = x509ext

        return dataset

    def housekeeping(self, autorenew=True, validity_period=None, cakey=None):
        """
        Check validity of certificates stored in the backend and update certificate status.
        :param autorenew: Renew autorenewable certificates
        :param validity_period: Set new validity period for autorenewable certificates
        :param cakey: CA private key for signing renewed certificates
        :return: None
        """

    def get_statistics(self):
        """
        Report statistics of stored certificates.
        :return: Dictionary of statistics.
        Keys:
        "state" - Dictionary of states with number of certificates in specific state
        """

    def _get_digest(self):
        """
        Returns configured message digest
        :return: digest (type string)
        """

    def sign_request(self, csr, notbefore, notafter, cakey, issuer, extensions, digest=None):
        """
        Create a certificate from a certificate signing request,
        :param csr: X509Request object of certificate signing request
        :param notbefore: start of validity period in days from now (can be None)
        :param notafter: end of validity period in days
        :param cakey: X509 object of CA signing key
        :param issuer: X509Name object containing the subject of CA
        :param extensions: list of x509 extension
        :param digest: digest for signing, if None it will be take from configuration
        :return: signed certificate as X509 object
        """

        # create new X509 object
        newcert = OpenSSL.crypto.X509()

        # SSL version 3, count starts at 0
        newcert.set_version(3 - 1)

        # copy subject from signing request
        newcert.set_subject(csr.get_subject())

        # copy public key from signing request
        newcert.set_pubkey(csr.get_pubkey())

        # set validity period
        newcert.gmtime_adj_notBefore(notbefore * 86400)
        newcert.gmtime_adj_notAfter(notafter * 86400)

        newcert.set_issuer(issuer)

        # obtain a new serial number
        new_serial_number = self._get_new_serial_number(newcert)

        if not new_serial_number:
            return None

        newcert.set_serial_number(new_serial_number)

        # insert new serial number to database to lock serial
        self._insert_empty_cert_data(new_serial_number, self._format_subject(newcert.get_subject().get_components()))

        # handle extensions
        if extensions and len(extensions) > 0:
            newcert.add_extensions(extensions)

        # sign new certificate
        if digest:
            signdigest = digest
        else:
            signdigest = self._get_digest()
        newcert.sign(cakey, signdigest)

        if newcert:
            # replace "locked" serial number with current certificate data
            self.store_certificate(newcert, csr=csr, revoked=None, replace=True)

        else:
            # remove "locked" serial number because certificate signing failed
            self.remove_certificate(new_serial_number)

        return newcert

    def remove_certificate(self, serial):
        """
        Removes certificate identified by it's serial number from the database
        :param serial: serial number of the certificate which should be removed
        :return: None
        """

    def insert_empty_cert_data(self, serial, subject, start=None, end=None):
        """
        Insert empty data to "lock" new serial number during certificate signing or to add a "dummy" certificate
        (e.g. a certificate with a known serial number but missing the real certificate)
        :param serial: serial number
        :param subject: subject string
        :param start: date when certificate becomes valid
        :param end: end of vailidity period for certificate
        :return: Nothing
        """
        if not subject:
            subject = serial

        self._insert_empty_cert_data(serial, subject)

        # we don't know the signing algorithm so set it to "placeholder"
        algo_id = self._store_signature_algorithm_name("placeholder")
        meta = {"signature_algorithm_id": algo_id, }
        if start or end:
            if start:
                meta["start_date"] = start
            if end:
                meta["end_date"] = end

        self._set_meta_data(serial, meta)

    def _insert_empty_cert_data(self, serial, subject):
        """
        Insert empty data to "lock" new serial number during certificate signing
        :param serial: serial number
        :param subject: subject string
        :return: Nothing
        """

    def generate_revocation_list(self):
        """
        Generate certificate revocation list from revoked certificates
        :return: CRL object
        """

    def revoke_certificate(self, serial, reason, revocation_date, force=False):
        """
        Revoke certificate identified by serial number
        :param serial: serial number
        :param reason: revocation reason
        :param revocation_date: revocation date as UNIX timestamp
        :param force: insert dummy data if the serial number does not exist in the database
        :return: None
        """

    def renew_certificate(self, serial, notbefore, notafter, cakey):
        """
        Renew a certificate identified by serial number
        :param serial: serial number
        :param notbefore: start of validity period as ASN1 GERNERALIZEDTIME string
        :param notafter: end of validity period as ASN1 GENERALIZEDTIME string
        :param cakey: X509 object of CA signing key
        :return: X509 object with renewed certificate
        """
        self.__logger.info("Renewing certificate with serial number %s" % (str(serial),))

        # check if the certificate has been revoked
        if self._is_revoked(serial):
            self.__logger.error("Certificate with serial number %s can't be renewed, "
                                "it has been revoked" % (serial,))
            raise PKIDBException(message="Certificate with serial number %s can't be renewed, "
                                         "it has been revoked" % (serial,))

        newcert = self.get_certificate(serial)
        if newcert:
            # set new validity dates
            newcert.set_notBefore(notbefore)
            newcert.set_notAfter(notafter)

            # resign certificate using the same signature algorithm
            newcert.sign(cakey, newcert.get_signature_algorithm())

            self.__logger.info("Certificate with serial number %s is now valid from %s til %s" %
                               (serial, notbefore, notafter))

            # commit new certificate
            self.store_certificate(newcert, replace=True)

        return newcert

    def dump_database(self):
        """
        Dumps content of the backend database as JSON output
        :return: database dump
        """

    def restore_database(self, dump):
        """
        Restores a database from dump
        :param dump: dump
        :return: True on success, False on failure
        """

    def list_serial_number_by_state(self, state):
        """
        Fetch all serial numbers with a given state or all if state is None
        :param state: state or None
        :return: List of serial numbers
        """

    def _get_raw_certificate_data(self, serial):
        """
        Like get_certificate_data but don't do an inner join (which will result in NULL if signature_algorithm_id
        becomes corrupt
        :param serial: serial
        :return: data
        """

    def get_certificate_data(self, serial):
        """
        Fetches certificate data from backend for certificate with serial number <serial>
        :param serial: serial number
        :return: certificate data
        """

    def set_certificate_metadata(self, serial, auto_renew=None, auto_renew_start_period=None,
                                 auto_renew_validity_period=None):
        """
        Sets meta data for a certificate identified by the serial number.
        :param serial: serial number
        :param auto_renew: auto renew flag
        :param auto_renew_start_period: auto renew start period
        :param auto_renew_validity_period: auto renew validity period
        :return: None if certificate was not found, True if the metadata were set, False if no meta data was given.
        """

    def _get_from_config_global(self, option):
        """
        Get value for option from global section of the configuration
        :param option: option
        :return: value or None
        """

    def _get_signature_algorithm(self, algo_id):
        """
        Get signature algorithm name based on its id
        :param algo_id: id
        :return: name
        """

    def healthcheck(self, fix=False):
        """
        Checks data from certificates with stored data
        :param fix: fix problems
        :return: tuple of two arrays (ok, notok) containing serial numbers that are ok or not ok
        """
        re_sn = re.compile("(\d+)\s\(0x[a-f0-9]+\)")
        metadata = ["auto_renewable",
                    "auto_renew_start_period",
                    "auto_renew_validity_period",
                    "state",
                    "revocation_date",
                    "revocation_reason",
                    "certificate",
                    "signing_request",
                    ]

        ok = []
        notok = []
        repaired = []

        try:
            serialnumbers = self.list_serial_number_by_state(None)
            for serial in serialnumbers:
                certstate = self._certificate_status_reverse_map[self._get_state(serial)]
                if certstate != "dummy" and certstate != "temporary":

                    cert = self.get_certificate(serial)
                    if not cert:
                        self.__logger.info("Empty certificate data from backend for serial number %s, skipping"
                                           % (serial,))
                        continue

                    certdbdata = self._get_raw_certificate_data(serial)
                    # extract data from ASN1 data of the certificate
                    certcontent = self._extract_data(cert)

                    # remove meta data fields not found in ASN1 data from certdata
                    for remove in metadata:
                        if remove in certdbdata:
                            certdbdata.pop(remove)
                        if remove in certcontent:
                            certcontent.pop(remove)

                    # calculate fields from certificate data and add it to certdata for comparison
                    if "start_date" in certdbdata:
                        certdbdata["start_date"] = self._date_string_to_unix_timestamp(certdbdata["start_date"])
                    else:
                        certdbdata["start_date"] = None

                    if "end_date" in certdbdata:
                        certdbdata["end_date"] = self._date_string_to_unix_timestamp(certdbdata["end_date"])
                    else:
                        certdbdata["end_date"] = None

                    # reformat serial number field
                    certdbdata["serial_number"] = long(re_sn.match(certdbdata["serial_number"]).groups()[0])

                    # try to map signature_algorithm_id to algorithm
                    if "signature_algorithm_id" in certdbdata:
                        certdbdata["algorithm"] = self._get_signature_algorithm(certdbdata["signature_algorithm_id"])
                        certdbdata.pop("signature_algorithm_id")
                    else:
                        certdbdata["algorithm"] = None

                    if not certdbdata["algorithm"]:
                        certdbdata["algorithm"] = "<UNKNOWN>"

                    # adjust for different key names
                    certcontent["fingerprint_md5"] = certcontent["fp_md5"]
                    certcontent.pop("fp_md5")

                    certcontent["fingerprint_sha1"] = certcontent["fp_sha1"]
                    certcontent.pop("fp_sha1")

                    certcontent["serial_number"] = certcontent["serial"]
                    certcontent.pop("serial")

                    certcontent["algorithm"] = self._get_signature_algorithm(certcontent["signature_algorithm_id"])
                    if not certcontent["algorithm"]:
                        certcontent["algorithm"] = "<unknown>"

                    certcontent.pop("signature_algorithm_id")

                    certcontent["version"] += 1

                    certcontent.pop("pubkey")

                    if "extension" in certcontent:
                        reformatted = []
                        for ext in certcontent["extension"]:
                            extdata = {"name": ext[0]}
                            if ext[1] == 1:
                                extdata["critical"] = True
                            else:
                                extdata["critical"] = False

                            extdata["data"] = base64.b64encode(ext[2])
                            reformatted.append(extdata)
                        certcontent["extension"] = reformatted
                    else:
                        certcontent["extension"] = []

                    for data in certdbdata.keys():
                        if certdbdata[data] != certcontent[data]:
                            self.__logger.warning("Content for %s differ (%s vs. %s) for serial number %s" %
                                                  (data, certdbdata[data], certcontent[data], serial))
                            if serial not in notok:
                                notok.append(serial)

                            if data == "serial_number":
                                self.__logger.critical("ATTENTION: Serial numbers does not match (database: %s / "
                                                       "certificate data: %s" % (certdbdata[data], certcontent[data]))

                            if fix:
                                # preserve meta data
                                metadata = self._get_meta_data(serial, self._metadata)

                                # except certificate, we already know this one
                                metadata.pop("certificate")

                                if metadata:
                                    # if the serial_number does not match the database is heavily damaged
                                    # it is considered beyound repair. this happens if the database has been
                                    # modified outside this programm. recommended action is dumping (pkidb export),
                                    # wiping and reinitialising the database and import the dumped certificates
                                    if data == "serial_number":
                                        self.__logger.critical("ATTENTION: Serial number mismatch!")
                                        self.__logger.critical("ATTENTION: To fix this export all certificates "
                                                               "(pkidb export),")
                                        self.__logger.critical("ATTENTION: wipe and reinitialise the database and "
                                                               "reimport ")
                                        self.__logger.critical("ATTENTION: the exported certifiates (pkidb import)!")
                                    else:
                                        self._set_meta_data(serial, metadata)
                                        # force rewrite of certificate data
                                        self.__logger.info("Regenerating and storing certificate data "
                                                           "for serial number %s." % (serial,))
                                        self.store_certificate(cert, replace=True)
                                        repaired.append(serial)
                                else:
                                    self.__logger.error("Failed to get meta data for certificate with serial number %s"
                                                        % (serial,))
                        else:
                            if serial not in ok:
                                ok.append(serial)
                            self.__logger.info("Content of %s is o.k. for serial number %s" % (data, serial))
                else:
                    self.__logger.info("Skipping %s certificate %s" % (certstate, serial))
        except Exception as error:
            self.__logger.error("Error while processing certifcate data: %s" % (error.message,))
            raise PKIDBException(message="Error: Error while processing certifcate data: %s" % (error.message,))

        return ok, notok, repaired

    def _get_meta_data(self, serial, fields=None):
        """
        Fetch metadata from backend
        :param serial: serial number to look up the meta data
        :param fields: if field is None or empty all metadata are returned, otherwise the requested fields
        :return: dictionary of metadata
        """

    def _set_meta_data(self, serial, metadata):
        """
        Set metadata in backend database for certifiate with a given serial number
        :param serial: serial number to set meta data for
        :param metadata: if dictionary containig meta data to set with their values
        :return: Nothing
        """

    def search_certificate(self, searchstring):
        """
        Search backend for searchstring
        :param searchstring: search string
        :return: tuple of serial numbers
        """
