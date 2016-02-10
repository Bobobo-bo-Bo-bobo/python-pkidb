#!/usr/bin/env python

import sys
import time

TIMEFORMAT = "%y%m%d%H%M%SZ"

if __name__ == "__main__":
    fd = None
    if len(sys.argv) == 1:
        fd = sys.stdin
    else:
        try:
            fd = open(sys.argv[1], "r")
        except IOError as ioerror:
            sys.stderr.write("Error: Can't open %s for reading: %s" % (sys.argv[1], ioerror.strerror))
            sys.exit(ioerror.errno)

    index_data = fd.readlines()
    fd.close()

    for line in index_data:
	# Format of index.txt is:
	# <flag>\t<expiration_time>\t[<revocation_time>]\t<serial>\tunknown\t<subject>
	#
	# Flags are:
	#  V - valid certificate
	#  R - revoked certificate
	#  E - expired certificate
	#
	# If the flag is set to "R" the optional field <revocation_time> is present.
	#
	# OpenSSL stores the time in DATETIME format:
	#
	# YYMMDDhhmmssZ
	#
        split_line = line.split()
        state = split_line[0]
        notafter_string = split_line[1]
	notafter = long(time.mktime(time.strptime(notafter_string, TIMEFORMAT)))

        # subject may contain multiple whitespace, split on "/"
        subject = "/" + "/".join(line.split("/")[1:])
        subject = subject.replace("\r", "")
        subject = subject.replace("\n", "")

        # is it marked as revoked ?
        if state == "R":
            revoked_asn1 = split_line[2]
            serial = split_line[3]
        else:
	    serial = split_line[2]
            revoked_asn1 = None

        print("pkidb add-dummy --subject=\"%s\" --end=%s 0x%s" % (subject, notafter, serial))
	if revoked_asn1:
            # either run revoke --force or add-dummy followed by revoke
            # use add-dummy followed by revoke to preserve start date and
            # certificate subject
            print("pkidb revoke --revocation-date=%s 0x%s" % (revoked_asn1, serial))

    sys.exit(0)

