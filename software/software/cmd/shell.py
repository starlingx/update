#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Command Line Interface for Unified Software Management
"""

import logging
import sys

BASENAME = 'software'
commands = ('capabilities', 'info', 'bash_completion')
logger = logging.getLogger(__name__)


class SoftwareShell:
    """CLI Shell"""
    def main(self, argv):
        """Parse and run the commands for this CLI"""
        print(f"Under construction {argv}")


def main():
    """Main entry point for CLI"""
    try:
        SoftwareShell().main(sys.argv[1:])
    except KeyboardInterrupt:
        print(f"... terminating {BASENAME} client", file=sys.stderr)
        sys.exit(130)
    except Exception as ex:  # pylint: disable=broad-exception-caught
        logger.debug(ex, exc_info=1)
        print(f"ERROR: {ex}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
