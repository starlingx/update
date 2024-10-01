"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from pecan import hooks
import logging

logger = None


def get_logger():
    global logger
    if logger is not None:
        return logger
    logger = logging.getLogger("RestAPI")
    handler = logging.FileHandler('/var/log/software-api.log')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger


class LoggingHook(hooks.PecanHook):
    def __init__(self):
        super().__init__()
        self.logger = get_logger()

    def on_route(self, state):
        skip_tags = ['X-Auth-Token']
        headers = state.request.headers
        headers = [f"{key}={headers[key]}" for key in headers if key not in skip_tags]
        headers = ' '.join(headers)
        msg = f"Request: {state.request.method} {state.request.path}, " \
              f"Headers: {headers}, " \
              f"Params: {state.request.params.mixed()}"
        self.logger.info(msg)

    def after(self, state):
        body = state.response.body.decode()
        msg = f"{state.request.method} {state.request.path}, " \
              f"{state.response.status}, " \
              f"Headers: {state.response.headers}, " \
              f"Body: {body}"

        status_code = int(state.response.status.split()[0])
        if status_code > 299 or status_code < 200:
            self.logger.error(msg)
        else:
            self.logger.info(msg)
