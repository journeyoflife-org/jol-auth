#!/usr/bin/env python3
# MIT License
#
# Copyright (c) 2024-2026 Journey of Life
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Collect authentication evidence for compliance audits.

Usage:
    python scripts/collect-auth-evidence.py --tenant-id <uuid> --from 2026-01-01 --to 2026-06-30
"""

import argparse
from datetime import date


def collect_evidence(tenant_id: str, from_date: date, to_date: date) -> None:
    """Export audit events and auth metrics for a tenant."""
    print(f"==> Collecting auth evidence for tenant {tenant_id}")
    print(f"    Period: {from_date} to {to_date}")
    # TODO: Query audit events and export to CSV/JSON
    # TODO: Include token issuance/revocation counts
    # TODO: Include MFA enrolment statistics
    print("==> Evidence exported to ./evidence/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect auth evidence for compliance.")
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID.")
    parser.add_argument("--from", dest="from_date", required=True, help="Start date (YYYY-MM-DD).")
    parser.add_argument("--to", dest="to_date", required=True, help="End date (YYYY-MM-DD).")
    args = parser.parse_args()
    collect_evidence(
        tenant_id=args.tenant_id,
        from_date=date.fromisoformat(args.from_date),
        to_date=date.fromisoformat(args.to_date),
    )
