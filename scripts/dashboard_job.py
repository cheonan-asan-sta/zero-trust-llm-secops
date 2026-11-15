"""Execute a previously authenticated, durable dashboard job."""

import argparse
from uuid import UUID

from app.services.dashboard_jobs import JobStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--job-id", type=UUID, required=True)
    args = parser.parse_args()
    JobStore(args.directory).run(str(args.job_id))


if __name__ == "__main__":
    main()
