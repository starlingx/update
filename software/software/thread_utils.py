"""
Copyright (c) 2026 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from functools import wraps
import threading

from software.software_functions import LOG


def threaded(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread
    return wrapper


def no_reentry(on_skip=None, on_skip_return_val=None):
    """Decorator that prevents a function from being invoked again while still running.

    :param on_skip: optional callable invoked with (*args, **kwargs) when the call is skipped
    """
    def decorator(func):
        lock = threading.Lock()

        @wraps(func)
        def wrapper(*args, **kwargs):
            if not lock.acquire(blocking=False):
                LOG.warning("%s is already running, skipping re-entrant call",
                            func.__name__)
                if on_skip:
                    on_skip(*args, **kwargs)
                return on_skip_return_val
            try:
                return func(*args, **kwargs)
            finally:
                lock.release()

        return wrapper
    return decorator
