#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import json
import sys

from software_client.release_file import get_release_info_list


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Show the release info of ISO and patch files as JSON")
    parser.add_argument("files", nargs="+", help="ISO or patch files (.sig files are skipped)")
    args = parser.parse_args(argv)

    results = get_release_info_list(args.files)
    print(json.dumps(results, indent=2))
    return 1 if any("error" in r for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
