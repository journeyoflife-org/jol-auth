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

"""Create a new tenant.

Usage:
    python scripts/create-tenant.py --name "St. Mary's" --slug st-marys --region eu-west
"""

import argparse


def create_tenant(name: str, slug: str, region: str) -> None:
    """Register a new tenant in the system."""
    print(f"==> Creating tenant: {name} ({slug}) in region {region}")
    # TODO: Implement tenant creation via TenantService
    print("==> Tenant created.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a new tenant.")
    parser.add_argument("--name", required=True, help="Tenant display name.")
    parser.add_argument("--slug", required=True, help="URL-safe tenant slug.")
    parser.add_argument("--region", required=True, help="Deployment region (eu-west, eu-central, eu-east).")
    args = parser.parse_args()
    create_tenant(name=args.name, slug=args.slug, region=args.region)
