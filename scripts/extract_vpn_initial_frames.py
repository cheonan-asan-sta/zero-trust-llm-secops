"""Extract pinned current initial-frame header observations; no model or labels."""

import argparse
import json

from scripts.f1_lab.pcap_initial import scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    print(json.dumps(scan(args.source, args.sha256, args.output)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
