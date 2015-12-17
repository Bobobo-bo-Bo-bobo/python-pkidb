#!/usr/bin/env python

import getopt
import os
import sys
import OpenSSL

# default configuration file
global configfile
configfile = "/etc/pki/config.ini"

global shortopts
global longopts

shortopts = "c:h"
longopts = ["config=", "help"]

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

    print("""Usage: %s [-c <cfg>|--config=<cfg>] [-h|--help] <command>

  -c <cfg>          Use configuration file instead of the default
  --config=<cfg>    Default: %s

  -h                This text
  --help
  """ % (os.path.basename(sys.argv[0])), configfile)


if __name__ == "__main__":

    # parse commandline options
    try:
        (optval, trailing) = getopt.getopt(sys.argv[1:], shortopts, longopts)
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
            sys.stderr.write("Error: Unknown option %s" % (opt,))
            sys.exit(1)

    options = parseoptions(configfile)

    sys.exit(0)
