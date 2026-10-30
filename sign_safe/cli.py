"""Command line interface; JSON output, exit 0 ALLOW / 2 DENY / 3 CONFIRM."""
import argparse
import json
import sys
from pathlib import Path
from . import explain, dumps, load_policy
from .decode.common import strict_json

def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m sign_safe')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('explain')
    p.add_argument('--type', required=True, choices=['eip7702', 'eip2612', 'permit2', 'raw_calldata'])
    p.add_argument('--payload', required=True)
    p.add_argument('--policy')
    p.add_argument('--now', type=int, help='Trusted Unix timestamp; enables relative expiry checks')
    args = parser.parse_args(argv)
    try:
        policy = load_policy(Path(args.policy).read_text()) if args.policy else None
        payload = strict_json(Path(args.payload).read_text())
        result = explain(payload, type=args.type, policy=policy, now=args.now)
    except (OSError, ValueError, TypeError) as exc:
        result = {'verdict': 'DENY', 'decoded': None,
                  'reasons': [{'verdict': 'DENY', 'code': 'INVALID_INPUT', 'message': str(exc)}],
                  'summary': 'DENY [INVALID_INPUT]: ' + str(exc)}
    print(dumps(result))
    return {'ALLOW': 0, 'DENY': 2, 'CONFIRM': 3}[result['verdict']]

if __name__ == '__main__':
    sys.exit(main())
