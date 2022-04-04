import asyncio
import logging
import sys

from . import __doc__, __package_name__, __version__
from .scanner import OpenApiSqliScanner

logger = logging.getLogger(__package_name__)
import argparse


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=__package_name__,
        description=__doc__,
    )
    parser.add_argument(
        'url',
        help='specification URL',
    )
    parser.add_argument(
        '-H',
        '--header',
        default=[],
        nargs='*',
        help='Additional header',
    )
    parser.add_argument(
        '--rate-limit',
        '--rate',
        default=100,
        help='requests per minute rate limit',
        type=int,
    )
    parser.add_argument(
        '--timeout',
        default=30,
        help='client timeout',
        type=float,
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        help='be more verbose',
    )
    parser.add_argument(
        '--version', action='version', version=f'%(prog)s v{__version__}'
    )
    return parser.parse_args(argv)


def main(argv: list[str] = sys.argv[1:]) -> None:
    args = _parse_args(argv)
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    log_levels = ['WARNING', 'INFO', 'DEBUG']
    lvl = log_levels[min(args.verbose, len(log_levels) - 1)]
    logger.setLevel(lvl)
    asyncio.run(
        OpenApiSqliScanner.run(
            args.url,
            headers=dict(map(lambda x: x.split(':', 2), args.header)),
            timeout=args.timeout,
            rate_limit=args.rate_limit,
        )
    )
