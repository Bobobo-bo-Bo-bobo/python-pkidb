#!/usr/bin/env python

import backends
import getopt
import re
import os
import sys
import time
import OpenSSL

# default configuration file
global configfile
configfile = "/etc/pki/config.ini"

global longoptions
global shortoptions

shortoptions = {
    "main":"c:h",
    "sign":"o:s:e:E:",
    "import":"c:r:",
    "housekeeping":"",
    "statistics":"",
    "gencrl":"o:",
    "revoke":"r:R:",
    "renew":"o:p:",
    "export":"o:",
}

longoptions = {
    "main":["config=", "help"],
    "sign":["output=", "start=", "end=", "extension="],
    "import":["csr=", "revoked="],
    "housekeeping":[],
    "statistics":[],
    "gencrl":["output="],
    "revoke":["reason=", "revocation-date="],
    "renew":["output=", "period="],
    "export":["output="],
}

# Python 3 renamed ConfigParser to configparser
if sys.version_info[0] < 3:
    import ConfigParser as configparser
else:
    import configparser

def mapconfigsections(config, section):
    """
    helper function to map ini sections and values
    :param config:  ConfigParser object
    :param section: section to parse
    :return:
    """
    resdict = {}
    options = config.options(section)

    for opt in options:
        try:
            resdict[opt] = config.get(section, opt)
            if resdict[opt] == -1:
                # skip option, remove from dictionary
                resdict.pop(opt)
        except configparser.Error as error:
            sys.stderr.write("Error: Error parsing ini file: %s\n" % (error.message,))
            return None
    return resdict

def parseoptions(optfile):
    """
    Parses an "ini style" option file, returns result
    as dictionary
    :param optfile: optionfile to parse
    :return: parsed options
    """
    result = {}
    config = configparser.ConfigParser()
    config.read(optfile)
    # loop over sections
    try:
        for section in config.sections():
            result[section] = mapconfigsections(config, section)
    except configparser.Error as error:
        sys.stderr.write("Error: Can't parse ini file %s: %s\n" % (optfile, error.message))
        result = None
    return result

def usage():

    print("""Usage: %s [-c <cfg>|--config=<cfg>] [-h|--help] <command> [<commandoptions>]

  -c <cfg>                      Use configuration file instead of the default
  --config=<cfg>                Default: %s

  -h                            This text
  --help

  Commands:

   export                       Dumps base64 encoded X509 data of a certificate (aka PEM format).
                                The serial number of the certificate must be given.
                                If not given it will be read from the standard input.
                                The new certificate will be written to standard output or to a file if
                                the -o option is used.

     -o <output>                Write new certificate to <output> instead of standard out
     --output=<output>

   gencrl                       Generate certificate revocation list from revoked certificates.
                                The certificate revocation list will be written to standard output
                                or to a file if -o is used.

     -o <output>                Write revocation list to <output> instead of standard output.
     --output=<output>

   housekeeping                 Generale "housekeeping. Checking all certificates in the database
                                for expiration, renew autorenewable certificates, ...
                                This should be run at regular intervals.

     -N                         Don't renew auto renawable certificates that will expire.
     --no-autorenew             This option can be used to when run as a cronjob and the CA key
                                should not be used (e.g. they are stored offline).

   import                       Import a certificate. If a file name is given it will be read
                                from the file, otherwise it will be read from stdin.

     -a                         Mark certificate as autorenwable.
     --autorenew                The "housekeeping" command will take care of this

     -c <csr>                   Certificate signing request used for certificate
     --csr=<csr>                creation. Optional.

     -r <reason>,<time>         Mark certificate as revoked. Optional.
     --revoked=<reason>,<time>  <time> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                string in the format YYYYMMDDhhmmssZ
                                <reason> can be one of:
                                unspecified, keyCompromise, CACompromise, affiliationChanged,
                                superseded, cessationOfOperation, certificateHold, privilegeWithdrawn,
                                removeFromCRL, aACompromise

   renew                        Renew a cerificate. The serial number of the certificate must be given.
                                If not given it will be read from the standard input.
                                The new certificate will be written to standard output or to a file if
                                the -o option is used.

     -o <output>                Write new certificate to <output> instead of standard out
     --output=<output>

     -p <period>                New validity period for renewed certificate.
     --period=<period>          Default <validity_period> from configuration file.

   revoke                       Revoke a certificate. Serial number of the certificate to revoke must
                                be used. If given not given on the command line it will be read from
                                stdin.

     -r <reason>                Set revocation reason for certificate.
     --reason=<reason>          <reason> can be one of:
                                unspecified, keyCompromise, CACompromise, affiliationChanged,
                                superseded, cessationOfOperation, certificateHold, privilegeWithdrawn,
                                removeFromCRL, aACompromise
                                If no reasen is given, the default "unspecified" is used.

     -R <date>                  Set revocation date for certificate.
     --revocation-date=<date>   <revdate> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                string in the format YYYYMMDDhhmmssZ.
                                If not given, the current date will be used.

   sign                         Sign a certificate signing request. If a file name is given it will be
                                read, otherwise it will be read from stdin. Output will be written to
                                stdout or to a file if -o option is used.

     -a                         Mark certificate as autorenwable.
     --autorenew                The "housekeeping" command will take care of this

     -E <extdata>               X509 extension. Can be repeated for multiple extensions.
     --extension=<extdata>      Parameter <extdata> is a komma separated list of:
                                <name> - Name of the X509 extension
                                <critical> - Criticality flag. 0: False, 1: True
                                <subject> - Subject, is usually empty
                                <issuer> - Issuer, is usually empty
                                <data> - data of the extension

     -S <san>                   subjectAltName extension
     --san=<san>                This is the same as --extension=subjectAltName,0,,,<san>
                                but as using the subjectAltName extension is the
                                most common extension this is an extra option.

     -s <start>                 Start time for new certificate as Unix timestamp
     --start=<start>            Default: now

     -e <end>                   End time for new certificate as Unix timestamp
     --end=<end>                Default: start + <validity_period> days.

     -o <out>                   Write data to <outfile> instead of stdout
     --output=<out>

   statistics                   Print small summary of stored certificates. Output will be written to
                                stdout.

  """ % (os.path.basename(sys.argv[0]), configfile))

def export_certificate(opts, config, backend):
    """
    Export a certificate identified by the serial number
    :param opts: options
    :param config: configuration
    :param backend: backend
    :return:
    """
    output = None

    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["export"], longoptions["export"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg))
        sys.exit(1)

    for (opt, val) in optval:
        if opt in ("-o", "--output"):
            output = val
        else:
            sys.stderr.write("Error: Unknown option %s\n" % (opt,))
            sys.exit(1)

    serial = None
    if len(trailing) == 0:
        serial = sys.stdin.read()
    else:
        serial = trailing[0]

    serial = serial_to_number(serial)
    cert = backend.get_certificate(serial)

    if not cert:
        sys.stderr.write("Error: No certificate with serial number %s found.\n" % (serial, ))
        sys.exit(2)

    pem_data = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

    if output:
        try:
            fd = open(output, "w")
            fd.write(pem_data)
            fd.close()
        except IOError as error:
            sys.stderr.write("Error: Can't write to output file %s: %s\n" % (output, error.strerror))
            sys.exit(error.errno)
    else:
        sys.stdout.write(pem_data)

def renew_certificate(opts, config, backend):
    """
    Renew a certificate identified by the serial number
    :param opts: options
    :param config: configuration
    :param backend: backend
    :return: None
    """

    validity_period = long(config["global"]["validity_period"])
    output = None

    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["renew"], longoptions["renew"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg))
        sys.exit(1)

    for (opt, val) in optval:
        if opt in ("-p", "--period"):
            try:
                validity_period = float(val)
            except ValueError as error:
                sys.stderr.write("Error: Can't parse validity period option %s: %s\n" % (val, error.message))
                sys.exit(2)
        elif opt in ("-o", "--output"):
            output = val
        else:
            sys.stderr.write("Error: Unknown option %s\n" % (opt,))
            sys.exit(1)

    serial = None
    if len(trailing) == 0:
        serial = sys.stdin.read()
    else:
        serial = trailing[0]

    serial = serial_to_number(serial)

    notbefore = time.time()
    notafter = notbefore + 86400. * validity_period

    notbefore = backend._unix_timestamp_to_asn1_time(notbefore)
    notafter = backend._unix_timestamp_to_asn1_time(notafter)

    ca_key = load_private_key(config, "ca_private_key", "ca_passphrase")

    newcert = backend.renew_certificate(serial, notbefore, notafter, ca_key)

    if not newcert:
        sys.stderr.write("Error: Can't find a certificate with serial number %s\n" % (serial, ))
        sys.exit(2)

    pem_data = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, newcert)
    if output:
        try:
            fd = open(output, "w")
            fd.write(pem_data)
            fd.close()
        except IOError as error:
            sys.stderr.write("Error: Can't write to output file %s: %s\n" % (output, error.strerror))
            return error.errno
    else:
        sys.stdout.write(pem_data)

    return None

def serial_to_number(serial):
    """
    Convert a string to the decimal value of serial number
    String can be a decimal number or hexadecimal (0x...)
    or hexadecimal separated by ":" (ca:fe:ba:be)
    :param serial: string containing serial number
    :return: decimal value of serial number string
    """
    re_serial_is_hex = re.compile("0x[0-9a-f]+")

    # convert serial number to a number
    try:
        # check for 0x...
        if re_serial_is_hex.match(serial):
            serial = long(serial, 16)
        # it contains ":" we assume it is hexadecimal
        elif serial.find(":") >= 0:
            serial = serial.replace(":", "")
            serial = long(serial, 16)
        # assuming decimal value
        else:
            serial = long(serial)
    except ValueError as error:
        sys.stderr.write("Error: Can't convert serial number %s: %s" % (serial, error.message))
        sys.exit(2)

    return serial

def revoke_certificate(opts, config, backend):
    """
    Revoke a certificate identified by the serial number
    :param opts: options
    :param config: configurationd
    :param backend: backend
    :return: None
    """

    re_asn1_time_string = re.compile("^\d{14}Z$")

    reason = "unspecified"
    rev_date = time.time()

    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["revoke"], longoptions["revoke"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg))
        sys.exit(1)

    for (opt, val) in optval:
        if opt in ("-R", "--revocation-date"):
            # ASN1 GENERALIZEDTIME string?
            if re_asn1_time_string.match(val):
                # convert to UNIX timestamp
                rev_date = time.mktime(time.strptime(val, "%Y%m%d%H%M%SZ"))

            try:
                rev_date = float(val)
            except ValueError as error:
                sys.stderr.write("Error Can't parse end time %s: %s\n" % (val, error.message))
                return 1
        elif opt in ("-r", "--reason"):
            if val.lower() in backend._revocation_reason_map:
                reason = val.lower()
            else:
                sys.stderr.write("Error: %s is not a valid revocation reason\n" % (val, ))
                sys.exit(2)
        else:
            sys.stderr.write("Error: Unknown option %s\n" % (opt,))
            sys.exit(1)

    if len(trailing) == 0:
        serial = sys.stdin.read()
    else:
        serial = trailing[0]

    serial = serial_to_number(serial)

    backend.revoke_certificate(serial, reason, rev_date)

def generate_certificate_revocation_list(opts, config, backend):
    """
    Generate certificate revocation list
    :param opts: options
    :param config: configurationd
    :param backend: backend
    :return: None
    """

    output = None

    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["gencrl"], longoptions["gencrl"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg))
        sys.exit(1)

    for (opt, val) in optval:
        if opt in ("-o", "--output"):
            output = val
        else:
            sys.stderr.write("Error: Unknown option %s" % (opt,))
            sys.exit(1)

    # load CRL signing keys
    crl_pub_key = load_public_key(config, "crl_public_key")
    crl_priv_key = load_private_key(config, "crl_private_key", "crl_passphrase")

    crl = backend.generate_revocation_list()

    crl_period = None
    if "crl_validity_period" in config["global"]:
        crl_period = long(config["global"]["crl_validity_period"])

    crl_data = None

    # CRL.export() parameter digest is available in pyopenssl 0.15
    if OpenSSL.__version__ >= "0.15":

        crl_digest = None
        if "crl_digest" in config["global"]:
            crl_digest = config["global"]["crl_digest"]

            crl_data = crl.export(crl_pub_key, crl_priv_key, type=OpenSSL.crypto.FILETYPE_PEM,
                                  days=crl_period, digest=crl_digest)

    else:
        crl_data = crl.export(crl_pub_key, crl_priv_key, type=OpenSSL.crypto.FILETYPE_PEM,
                              days=crl_period)

    if output:
        try:
            fd = open(output, "w")
            fd.write(crl_data)
            fd.close()
        except IOError as error:
            sys.stderr.write("Error: Can't write CRL data to output file %s: %s\n" % (output, error.strerror))
            sys.exit(error.errno)
    else:
        sys.stdout.write(crl_data)

def sign_certificate(opts, config, backend):
    """
    Sign a certificate signing request.
    :param opts: array with options
    :param config: parsed configuration file
    :param backend: backend object
    :return: 0 on success or !=0 otherwise
    """

    output = None
    extensions = []
    input = None
    start = None
    end = None

    re_asn1_time_string = re.compile("^\d{14}Z$")

    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["sign"], longoptions["sign"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg))
        sys.exit(1)

    for (opt, val) in optval:
        if opt in ("-E", "--extension"):
            ext = val.split(",", 4)
            if len(ext) != 5:
                sys.stderr.write("Error: Illegal number of fields for extension (expect:%u got %u)\n" %(4, len(ext)))
            name = None
            subject = None
            issuer = None
            data = None

            name = ext[0]
            if ext[1] in ("1", "True"):
                critical = True
            else:
                critical = False

            if ext[2] == '':
                subject = None
            else:
                subject = ext[2]

            if ext[3] == '':
                issuer = None
            else:
                issuer = ext[3]

            data = ext[4]

            # append new extension object
            extensions.append(OpenSSL.crypto.X509Extension(name, critical, data, subject=subject, issuer=issuer))
        elif opt in ("-e", "--end"):
            end = val

            # ASN1 GENERALIZEDTIME string?
            if re_asn1_time_string.match(end):
                # convert to UNIX timestamp
                end = time.mktime(time.strptime(end, "%Y%m%d%H%M%SZ"))

            try:
                end = float(val)
            except ValueError as error:
                sys.stderr.write("Error Can't parse end time %s: %s\n" % (val, error.message))
                return 1

        elif opt in ("-s", "--start"):
            start = val

            # ASN1 GENERALIZEDTIME string?
            if re_asn1_time_string.match(start):
                # convert to UNIX timestamp
                start = time.mktime(time.strptime(start, "%Y%m%d%H%M%SZ"))

            try:
                start = float(val)
            except ValueError as error:
                sys.stderr.write("Error Can't parse start time %s: %s\n" % (val, error.message))
                return 1

        elif opt in ("-o", "--output"):
            output = val

        else:
            sys.stderr.write("Error: Unknown option %s" % (opt,))
            sys.exit(1)

    # basic validation of options
    if not start:
        start = time.time()

    if not end:
        end = start + long(config["global"]["validity_period"])*86400.

    if start >= end:
        sys.stderr.write("Error: Start time (%f) is >= end time (%f)\n" % (start, end))
        return 1

    if len(trailing) == 0:
        input = sys.stdin

    elif len(trailing) == 1:
        try:
            input = open(trailing[0], "r")
        except IOError as error:
            sys.stderr.write("Error: Can't open %s for reading: %s" %(trailing[0], error.strerror))
            return error.errno

    else:
        sys.stderr.write("Error: Too much arguments. Expect zero or one, got %u instead\n" % (len(trailing),))
        return 1

    # csr read data from input
    try:
        data = input.read()
    except IOError as error:
        sys.stderr.write("Error: Read from %s failed: %s" % (input.name, error.strerror))
        return error.errno

    # close non stdin input
    if input != sys.stdin:
        input.close()

    # assuming PEM input
    csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, data)

    # X509Req.get_extensions() is available in pyopenssl 0.15
    if OpenSSL.__version__ >= "0.15":
        # FIXME: Handle get_extensions()
        pass

    # load private CA key
    ca_priv_key = load_private_key(config, "ca_private_key", "ca_passphrase")
    if not ca_priv_key:
        sys.stderr.write("Error: Failed to load CA private key\n")
        return 2

    ca_pub_key = load_public_key(config, "ca_public_key")
    if not ca_pub_key:
        sys.stderr.write("Error: Failed to load CA public key\n")
        return 2

    # set start and and time
    # Note: start/end time must be formatted as ASN1 GENERALIZEDTIME string
    #
    # YYYYMMDDhhmmssZ
    # YYYYMMDDhhmmss+hhmm
    # YYYYMMDDhhmmss-hhmm
    #
    asn1_start = time.strftime("%Y%m%d%H%M%S%z", time.localtime(start))
    asn1_end = time.strftime("%Y%m%d%H%M%S%z", time.localtime(end))

    # We do not pass the issuer of the CA, because only for root CA is issuer == subject
    # Intermediate CAs will contain their issuing CA as issuer
    newcert = backend.sign_request(csr, asn1_start, asn1_end, ca_priv_key, ca_pub_key.get_subject(), extensions)

    newcert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, newcert)

    if output:
        try:
            fd = open(output, "w")
            fd.write(newcert_pem)
            fd.close()
        except IOError as error:
            sys.stderr.write("Error: Can't open output file %s for writing: %s\n" % (output, error.strerror))
            sys.exit(error.errno)
    else:
        sys.stdout.write(newcert_pem)

def load_public_key(config, keyname):
    """
    Loads issuer from CA public key
    :param config: configuration
    :param keyname: name of public key in [global] section
    :return: X509 object representing CA public key
    """

    result = None
    try:
        fd = open(config["global"][keyname], "r")
        data = fd.read()
        fd.close()
    except IOError as error:
        sys.stderr.write("Error: Can't read public key %s: %s\n" % (config["global"][keyname], error.strerror, ))
        return None

    try:
        pubkey = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, data)
    except OpenSSL.crypto.Error as error:
        sys.stderr.write("Error: Invalid public key: %s\n" % (error.message, ))
        return None

    return pubkey

def load_private_key(config, keyname, passphrase):
    """
    Load CA keyfile
    :param config: configuration
    :param keyname: name of private key in [global] section
    :param passphrase: name of passphrase variable in [global] section
    :return: private CA key as PKey object or None
    """

    result = None
    key_passphrase = config["global"][passphrase]

    try:
        fd = open(config["global"][keyname], "r")
        data = fd.read()
        fd.close()
    except IOError as error:
        sys.stderr.write("Error: Can't read private key %s: %s\n" % (config["global"][keyname], error.strerror, ))
        return None

    try:
        result = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, data, passphrase=key_passphrase)
    except OpenSSL.crypto.Error as error:
        sys.stderr.write("Error: Can't load private key: %s\n" % (error.message, ))
        return None

    return result

def import_certificate(opts, config, backend):
    """
    Import a certificate (PEM) into the backend
    :param opts: options for import
    :param config: parsed configuration file
    :param backend: backend object
    :return: 0 on success, != 0 otherwise
    """

    re_asn1_time_string = re.compile("^\d{14}Z$")
    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["import"], longoptions["import"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg, ))
        return 1

    csr = None
    revoked = None

    for (opt, val) in optval:
        if opt in ("-c", "--csr"):
            try:
                fd = open(val, "r")
                csrdata = fd.read()
                fd.close()
            except IOError as error:
                sys.stderr.write("Error: Can't read certificate signing request from %s: %s\n" % (val, error.strerror))
                return error.errno

            csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csrdata)
        elif opt in ("-r", "--revoked"):
            # format: <reason>,<revocation_stamp>
            (reason, revtime) = val.split(',')

            # ASN1 GENERALIZEDTIME string?
            if re_asn1_time_string.match(revtime):
                # convert to UNIX timestamp
                revtime = time.mktime(time.strptime(revtime, "%Y%m%d%H%M%SZ"))

            # check timestamp
            try:
                revtime = float(revtime)
            except ValueError as error:
                sys.stderr.write("Error: Illegal timestamp %s\n" % (revtime, ))
                return 1

            # treat no reason as unspecified
            if reason == '':
                reason = "unspecified"

            # check reason string
            if reason.lower() in backend._revocation_reason_map:
                revoked = (backend._revocation_reason_map[reason.lower()], revtime)
            else:
                sys.stderr.write("Error: Unknown revocation reason %s\n" % (reason, ))
                return 1

    input = None

    if len(trailing) == 0:
        input = sys.stdin

    elif len(trailing) == 1:
        try:
            input = open(trailing[0], "r")
        except IOError as error:
            sys.stderr.write("Error: Can't open %s for reading: %s\n" %(trailing[0], error.strerror))
            return error.errno

    else:
        sys.stderr.write("Error: Too much arguments. Expect zero or one, got %u instead\n" % (len(trailing),))
        return 1

    try:
        data = input.read()
    except IOError as error:
        sys.stderr.write("Error: Read from %s failed: %s\n" % (input.name, error.strerror))
        return error.errno

    # close non stdin input
    if input != sys.stdin:
        input.close()

    # assuming PEM input
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, data)
    backend.store_certificate(cert, csr, revoked)

def housekeeping(opts, config, backend):
    """
    Check certificates in the backend for expiration, auto renew autorenewable certificates.
    :param opts: options for import
    :param config: parsed configuration file
    :param backend: backend object
    :return: None
    """
    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["housekeeping"], longoptions["housekeeping"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg, ))
        return 1

    for (opt, val) in optval:
        pass

    backend.validate_certficates()
    return None

def print_statistics(opts, config, backend):
    """
    Print statistics of certificates in the backend database.
    :param opts: options for import
    :param config: parsed configuration file
    :param backend: backend object
    :return: None
    """
    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["statistics"], longoptions["statistics"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg, ))
        return 1

    for (opt, val) in optval:
        pass

    stats = backend.get_statistics()

    for stat_type in stats:
        for key in stats[stat_type]:
            print("%s:%s:%u" % (stat_type, key, stats[stat_type][key]))

    return None

if __name__ == "__main__":

    # parse commandline options
    try:
        (optval, trailing) = getopt.getopt(sys.argv[1:], shortoptions["main"], longoptions["main"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg))
        sys.exit(1)

    for (opt, val) in optval:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif opt in ("-c", "--config"):
            configfile = val
        else:
            sys.stderr.write("Error: Unknown option %s\n" % (opt,))
            sys.exit(1)

    if not os.access(configfile, os.R_OK):
        sys.stderr.write("Error: Can't open configuration file %s for reading\n" % (configfile, ))
        sys.exit(1)

    options = parseoptions(configfile)

    # FIXME: Validate options

    backend = None

    # create backend object
    if "backend" in options["global"]:
        if options["global"]["backend"] == "pgsql":
            import backends.pgsql
            backend = backends.pgsql.PostgreSQL(options)

    if len(trailing) == 0:
        sys.stderr.write("Error: Missing command\n")
        usage()
        sys.exit(1)

    command = trailing[0]
    if command == "sign":
        sign_certificate(trailing[1:], options, backend)
    elif command == "help":
        usage()
        sys.exit(0)
    elif command == "import":
        import_certificate(trailing[1:], options, backend)
    elif command == "housekeeping":
        housekeeping(trailing[1:], options, backend)
    elif command == "statistics":
        print_statistics(trailing[1:], options, backend)
    elif command == "gencrl":
        generate_certificate_revocation_list(trailing[1:], options, backend)
    elif command == "revoke":
        revoke_certificate(trailing[1:], options, backend)
    elif command == "renew":
        renew_certificate(trailing[1:], options, backend)
    elif command == "export":
        export_certificate(trailing[1:], options, backend)
    else:
        sys.stderr.write("Error: Unknown command %s\n" % (command,))
        usage()
        sys.exit(1)
    sys.exit(0)
