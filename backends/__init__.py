#!/usr/bin/env python

import base64
import hashlib
import time
import re
import OpenSSL

__all__ = [ "pgsql"]
class Backend(object):
    def __init__(self, config):
        """
        Constructor
        :param config: dictionary of parsed configuration options
        :return: Nothing
        """
    pass


    def get_new_serial_number(self, cert):
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

    def store_certificate(self, cert, csr=None, revoked=None):
        """
        Stores a certificate in the backend.
        :param cert: X509 object to store
        :param csr: Optional, X509Req object
        :param revoked: Tuple with revocation information (reason, revocationtime).
                        if not set to None it marks the certificate as revoked.
        :return: None
        """
        pass

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
            "state":1
        }

        if csr:
            dataset["csr"] = base64.b64encode(OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, csr))

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
                data = base64.b64encode(extenstion.get_data())

                x509ext.append((name, criticality, data))

        return dataset