#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
API console script for Unified Software Management
"""
import gc
import socket
from wsgiref import simple_server

from oslo_log import log as logging
from software.api.app import setup_app


LOG = logging.getLogger(__name__)

# todo(abailey): these need to be part of config
API_PORT = 5496
# Limit socket blocking to 5 seconds to allow for thread to shutdown
API_SOCKET_TIMEOUT = 5.0


class RestAPI():
    """The base WSGI application"""
    def __init__(self):
        self.app = setup_app()
        self.running = False

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)


class MyHandler(simple_server.WSGIRequestHandler):
    """Overridden WSGIReqestHandler"""
    def address_string(self):
        # In the future, we could provide a config option to allow
        # reverse DNS lookups.
        return self.client_address[0]


def main():
    """Main entry point for API"""
    # todo(abailey): process configuration
    host = "127.0.0.1"
    port = API_PORT

    # todo(abailey): configure logging
    LOG.info(" + Starting Unified Software Management API")

    try:
        simple_server.WSGIServer.address_family = socket.AF_INET
        wsgi = simple_server.make_server(
            host, port,
            RestAPI(),
            handler_class=MyHandler
        )
        wsgi.socket.settimeout(API_SOCKET_TIMEOUT)

        running = True
        while running:  # run until an exception is raised
            wsgi.handle_request()

            # Call garbage collect after wsgi request is handled,
            # to ensure any open file handles are closed in the case
            # of an upload.
            gc.collect()
    except KeyboardInterrupt:
        LOG.warning(" - Received Control C. Shutting down.")
    except BaseException:  # pylint: disable=broad-exception-caught
        LOG.exception(" - Unhandled API exception")
    LOG.info(" - Stopping Unified Software Management API")


if __name__ == "__main__":
    main()
