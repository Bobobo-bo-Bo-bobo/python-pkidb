#!/usr/bin/env python

import base64
import hashlib
import time
import re
import OpenSSL

__all__ = [ "pgsql"]
class Backend(object):

    # Note: RFC 3280 (4.1.2.2  Serial number) states the serial number
    # must be:
    #  * unique
    #  * non-negative integer
    #  * up to 20 octets (up to 2**160)
    #  * not longer than 20 octets
    _MAX_SERIAL_NUMBER = 0x7fffffffffffffff

    _certificate_status_reverse_map = {
       -1:"temporary",
        0:"pending",
        1:"valid",
        2:"revoked",
        3:"expired",
        4:"invalid",
    }

    _certificate_status_map = {
        "temporary":-1,
        "pending":0,
        "valid":1,
        "revoked":2,
        "expired":3,
        "invalid":4,
    }

    _revocation_reason_map = {
        "unspecified":0,
        "keycompromise":1,
        "cacompromise":2,
        "affiliationchanged":3,
        "superseded":4,
        "cessationofoperation":5,
        "certificatehold":6,
        "unspecified (not used as defined in RFC5280)":7,
        "removefromcrl":8,
        "privilegewithdrawn":9,
        "aacompromise":10,
    }

    _revocation_reason_reverse_map = {
        0:"unspecified",
        1:"keycompromise",
        2:"cacompromise",
        3:"affiliationchanged",
        4:"superseded",
        5:"cessationofoperation",
        6:"certificatehold",
        7:"unspecified (not used as defined in RFC5280)",
        8:"removefromcrl",
        9:"privilegewithdrawn",
        10:"aacompromise",
    }

    def __init__(self, config):
        """
        Constructor
        :param config: dictionary of parsed configuration options
        :return: Nothing
        """
        pass

    def _has_serial_number(self, serial):
        """
        Check the backend for serial number
        :param serial: serial number to check for
        :return: True - if serial number was found
                 False - if serial number was not found
                 None - on error
        """
        return None

    def _get_last_serial_number(self):
        """
        Returns the last serial number
        :return: Last serial number
        """
        return None

    def _get_new_serial_number(self, cert):
        """
        Generate a new serial number. To avoid clashes the serial number will be written to the backend.
        Stale data should be removed by the signal handler and/or by running the backendcheck handler.
        :param cert: X509 object of new certificate
        :return: serial number
        """
        return None

    def __del__(self):
        """
        Destructor, close database connection
        :return: Nothing
        """
        pass

    def store_certificate(self, cert, csr=None, revoked=None, replace=False):
        """
        Stores a certificate in the backend.
        :param cert: X509 object to store
        :param csr: Optional, X509Req object
        :param revoked: Tuple with revocation information (reason, revocationtime).
                        if not set to None it marks the certificate as revoked.
        :param replace: Replace existing certificate, default is False
        :return: None
        """
        return None

    def _format_subject(self, subject):
        """
        Returns the subject as string from the tuple obtained from X509.get_subject().get_components()
        :param subject: subject tuple
        :return: string
        """

        result = ""
        intermediate = []
        for pair in subject:
            intermediate.append('='.join(pair))

        # subject start with /
        result = '/' + '/'.join(intermediate)

        return result

    def _unix_timestamp_to_asn1_time(self, timestamp):
        """
        Converts UNIX timestamp to ASN1 GENERALIZEDTIME string
        :param timestamp: UNIX timestamp
        :return: ASN1 GENERALIZEDTIME string
        """

        asn1_time = time.strftime("%Y%m%d%H%M%S%z", time.localtime(timestamp))
        return asn1_time

    def _asn1_time_to_unix_timestamp(self, asn1_time):
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
        re_asn1_with_Z = re.compile("^\d{14}Z$")
        re_asn1_with_offset = re.compile("^(\d{14})[+|-](\d{4})$")

        if re_asn1_with_Z.match(asn1_time):
            timestamp = time.mktime(time.strptime(asn1_time, "%Y%m%d%H%M%SZ"))
        elif re_asn1_with_offset.match(asn1_time):
            # although time.strftime supports %z time.strptime does not
            # split string into date and timeoffset
            date = re_asn1_with_offset.match(asn1_time).groups()[0]
            offset = re_asn1_with_offset.match(asn1_time).groups()[1]

            timestamp = time.mktime(time.strptime(date, "%Y%m%d%H%M%S"))
            timestamp += 3600.00 * float(offset) / 100.00

        return timestamp

    def _store_extension(self, extlist):
        """
        Stores list of X509 extensions into the backend.
        :param extlist: List of x509 extension data. X509 extension
        data is an array containing [<name>,<critical>,<data>]

        :return: Returns list of primary keys for <extlist> from
        the databasebackend. If extensions don't exist in the database
        they will be inserted.
        """
        return []

    def _store_request(self, csr):
        """
        Stores certificate signing request
        :param csr: base64 encoded X509 data of certificate signing request
        :return: primary key of csr
        """
        return None

    def _store_signature_algorithm(self, cert):
        """
        Stores signature algorithm
        :param cert: X509 object
        :return: primary key of signature algorithm in lookup table
        """
        return None

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
            "subject":self._format_subject(cert.get_subject().get_components()),
            "version":cert.get_version(),
            "start_date":self._asn1_time_to_unix_timestamp(cert.get_notBefore()),
            "end_date":self._asn1_time_to_unix_timestamp(cert.get_notAfter()),
            "serial":cert.get_serial_number(),
            "issuer":self._format_subject(cert.get_issuer().get_components()),
            "pubkey":base64.b64encode(certificate),
            "fp_md5":hashlib.md5(certificate).hexdigest(),
            "fp_sha1":hashlib.sha1(certificate).hexdigest(),
            "keysize":cert.get_pubkey().bits(),
            "signature_algorithm_id":self._store_signature_algorithm(cert),
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

    def validate_certficates(self):
        """
        Check validity of certificates stored in the backend and update certificate status.
        :return: None
        """
        return None

    def get_statistics(self):
        """
        Report statistics of stored certificates.
        :return: Dictionary of statistics.
        Keys:
        "state" - Dictionary of states with number of certificates in specific state
        """
        return None

    def _get_digest(self):
        """
        Returns configured message digest
        :return: digest (type string)
        """
        return None

    def sign_request(self, csr, notBefore, notAfter, cakey, issuer, extensions):
        """
        Create a certificate from a certificate signing request,
        :param csr: X509Request object of certificate signing request
        :param notBefore: start of validity period as ASN1 GERNERALIZEDTIME string
        :param notAfter: end of validity period as ASN1 GENERALIZEDTIME string
        :param cakey: X509 object of CA signing key
        :param issuer: X509Name object containing the subject of CA
        :param extension: list of x509 extension
        :return: signed certificate as X509 object
        """
        # create new X509 object
        newcert = OpenSSL.crypto.X509()

        # SSL version 3, count starts at 0
        newcert.set_version(3-1)

        # copy subject from signing request
        newcert.set_subject(csr.get_subject())

        # copy public key from signing request
        newcert.set_pubkey(csr.get_pubkey())

        # set validity period
        newcert.set_notBefore(notBefore)
        newcert.set_notAfter(notAfter)

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
        newcert.sign(cakey, self._get_digest())

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
        return None

    def _insert_empty_cert_data(self, serial, subject):
        """
        Insert empty data to "lock" new serial number during certificate signing
        :param serial: serial number
        :param subject: subject string
        :return: Nothing
        """
        return None

    def generate_revocation_list(self):
        """
        Generate certificate revocation list from revoked certificates
        :return: CRL object
        """
        return None

    def revoke_certificate(self, serial, reason, revocation_date):
        """
        Revoke certificate identified by serial number
        :param serial: serial number
        :param reason: revocation reason
        :param revocation_date: revocation date as UNIX timestamp
        :return: None
        """
        return None
