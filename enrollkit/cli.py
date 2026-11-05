"""Command line entry point for enrollkit.

The CLI is how most people meet a protocol library, so it is part of the public surface and
gets the same typing and testing discipline as the rest of the package.
"""

from __future__ import annotations

import argparse
import sys

USAGE = """\
Examples:
  enrollkit est --url https://ca.example/simpleenroll --key device.key --csr device.csr"""


def build_parser():
    return argparse.ArgumentParser(
        prog="enrollkit",
        description="Certificate enrollment: CMP to RFC 9810 with CRMF requests, EST to RFC 7030, PKCS#10 fallback, and the challenge and authentication mechanics around them",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv=None):
    """Parse arguments, then refuse to pretend the protocol works.

    Exiting non-zero is the correct behaviour for a shell. A CLI that printed a friendly
    banner and exited 0 would be indistinguishable from one that actually did something.
    """
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_usage(sys.stderr)
    print("enrollkit: no protocol behaviour is implemented yet; see ROADMAP.md", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
