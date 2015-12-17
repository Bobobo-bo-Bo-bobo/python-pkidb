#!/usr/bin/env python

import backends
import getopt
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
    "sign":"o:S:",
    "import":"",
}

longoptions = {
    "main":["config=", "help"],
    "sign":["output=", "san="],
    "import":[],
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

  -c <cfg>              Use configuration file instead of the default
  --config=<cfg>        Default: %s

  -h                    This text
  --help

  Commands:
   sign
     * Options:
     -S <san>           List of subjectAlternateName data.
     --san=<san>

     -s <start>         Start time for new certificate as Unix timestamp
     --start=<start>    Default: now

     -e <end>           End time for new certificate as Unix timestamp
     --end=<end>        Default: start + <validity_period> days.

     -o <out>           Write data to <outfile> instead of stdout
     --output=<out>

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
    san = []
    input = None
    start = None
    end = None

    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["sign"], longoptions["sign"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg))
        sys.exit(1)

    for (opt, val) in optval:
        if opt in ("-S", "--san"):
            san = val.split(",")

        elif opt in ("-e", "--end"):
            try:
                end = float(val)
            except ValueError as error:
                sys.stderr.write("Error: Can't parse end time %s: %s\n" % (val, error.message))
                return 1

        elif opt in ("-s", "--start"):
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
    cakey = load_ca_key(config)

    if not cakey:
        sys.stderr.write("Error: Failed to load CA private key\n")
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

    # create new X509 object
    certificate = OpenSSL.crypto.X509()

    # SSL version 3, Note: version starts at 0
    certificate.set_version(2)

    # copy subject from certificate signing request
    certificate.set_subject(csr.get_subject())

    # copy public key from certificate signing request
    certificate.set_pubkey(csr.get_pubkey())

    # set start and end dates
    certificate.set_notBefore(asn1_start)
    certificate.set_notAfter(asn1_end)

    # get new serial number for certificate
#    serial = get_new_serial_number(config, certificate)



def load_ca_key(config):
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
    :param ops: options for import
    :param config: parsed configuration file
    :param backend: backend object
    :return: 0 on success, != 0 otherwise
    """

    try:
        (optval, trailing) = getopt.getopt(opts, shortoptions["import"], longoptions["import"])
    except getopt.GetoptError as error:
        sys.stderr.write("Error: Can't parse command line: %s\n" % (error.msg, ))
        return 1

    for (opt, val) in optval:
        pass

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

    for i in range(cert.get_extension_count()):
        print(i," -> ", cert.get_extension(i).get_short_name(), " / ", cert.get_extension(i).get_critical(), " / ", cert.get_extension(i).get_data())

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
    else:
        sys.stderr.write("Error: Unknown command %s\n" % (command,))
        usage()
        sys.exit(1)

    sys.exit(0)
