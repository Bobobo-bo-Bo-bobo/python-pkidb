#!/usr/bin/env python

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
