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

global shortoptions
global longoptions

shortoptions = {
    "main":"c:h",
    "sign":"o:s:e:E:",
    "import":"c:r:",
    "expire":"",
    "statistics":"",
}

longoptions = {
    "main":["config=", "help"],
    "sign":["output=", "start=", "end=", "exension="],
    "import":["csr=", "revoked="],
    "expire":[],
    "statistics":[],
}

# map revocation reasons to numeric codes
# reasonFlag is defined in RFC 5280, 5.3.1. Reason Code
global revocation_reason_map

revocation_reason_map = {
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
   expire                       Checks all certificates in the database for expiration.

   import                       Import a certificate

     -c <csr>                   Certificate signing request used for certificate
     --csr=<csr>                creation. Optional.

     -r <reason>,<time>         Mark certificate as revoked. Optional.
     --revoked=<reason>,<time>  <time> is the UNIX epoch of the revocation or ASN1 GERNERALIZEDTIME
                                string in the format YYYYMMDDhhmmssZ
                                <reason> can be one of:
                                unspecified, keyCompromise, CACompromise, affiliationChanged,
                                superseded, cessationOfOperation, certificateHold, privilegeWithdrawn,
                                removeFromCRL, aACompromise

   sign

     -e <extdata>               X509 extension. Can be repeated for multiple extensions.
     --extension=<extdata>      Parameter <extdata> is a komma separated list of:
                                <name> - Name of the X509 extension
                                <critical> - Criticality flag. 0: False, 1: True
                                <subject> - Subject, is usually empty
                                <issuer> - Issuer, is usually empty
                                <data> - data of the extension

     -s <start>                 Start time for new certificate as Unix timestamp
     --start=<start>            Default: now

     -e <end>                   End time for new certificate as Unix timestamp
     --end=<end>                Default: start + <validity_period> days.

     -o <out>                   Write data to <outfile> instead of stdout
     --output=<out>

   statistics                   Print small summary of stored certificates

  """ % (os.path.basename(sys.argv[0]), configfile))

def sign(opts, config, backend):
    """
    Sign a certificate signing request.
    :param opts: array with options
    :param config: parsed configuration file
    :param back: backend object
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
        end = start + long(config["global"]["validity_period"])

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
    ca_priv_key = load_ca_private_key(config)
    if not ca_priv_key:
        sys.stderr.write("Error: Failed to load CA private key\n")
        return 2

    ca_pub_key = load_ca_public_key(config)
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

def load_ca_public_key(config):
    """
    Loads issuer from CA public key
    :param config: configuration
    :return: X509 object representing CA public key
    """

    result = None
    try:
        fd = open(config["global"]["ca_public_key"], "r")
        data = fd.read()
        fd.close()
    except IOError as error:
        sys.stderr.write("Error: Can't read CA public key: %s\n" % (error.strerror, ))
        return None

    try:
        ca_pubkey = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, data)
    except OpenSSL.crypto.Error as error:
        sys.stderr.write("Error: Invalid CA public key: %s\n" % (error.message, ))
        return None

    return ca_pubkey

def load_ca_private_key(config):
    """
    Load CA keyfile
    :param config: configuration
    :return: private CA key as PKey object or None
    """

    result = None
    ca_passphrase = config["global"]["ca_passphrase"]

    try:
        fd = open(config["global"]["ca_private_key"], "r")
        data = fd.read()
        fd.close()
    except IOError as error:
        sys.stderr.write("Error: Can't read CA private key: %s\n" % (error.strerror, ))
        return None

    try:
        result = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, data, passphrase=ca_passphrase)
    except OpenSSL.crypto.Error as error:
        sys.stderr.write("Error: Can't load CA private key: %s\n" % (error.message, ))
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
            if reason.lower() in revocation_reason_map:
                revoked = (revocation_reason_map[reason.lower()], revtime)
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

def check_expiration(opts, config, backend):
    """
    Check certificates in the backend for expiration.
    :param opts: options for import
    :param config: parsed configuration file
    :param backend: backend object
    :return: None
    """
    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["expire"], longoptions["expire"])
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
        (optval, trailing) = getopt.getopt(opts, shortoptions["expire"], longoptions["expire"])
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
        sign(trailing[1:], options, backend)
    elif command == "help":
        usage()
        sys.exit(0)
    elif command == "import":
        import_certificate(trailing[1:], options, backend)
    elif command == "expire":
        check_expiration(trailing[1:], options, backend)
    elif command == "statistics":
        print_statistics(trailing[1:], options, backend)
    else:
        sys.stderr.write("Error: Unknown command %s\n" % (command,))
        usage()
        sys.exit(1)
    sys.exit(0)
