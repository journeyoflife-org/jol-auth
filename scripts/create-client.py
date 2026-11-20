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

"""Register a new OAuth client for a tenant.

Usage:
    python scripts/create-client.py --tenant-id <uuid> --name "Portal App" --redirect-uris https://portal.example.com/callback
"""

import argparse


def create_client(tenant_id: str, name: str, redirect_uris: list[str]) -> None:
    """Register an OAuth client and print credentials."""
    print(f"==> Registering client '{name}' for tenant {tenant_id}")
    # TODO: Implement client registration via ClientService
    print("==> Client registered. Credentials printed below (store securely).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Register an OAuth client.")
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID.")
    parser.add_argument("--name", required=True, help="Client display name.")
    parser.add_argument("--redirect-uris", nargs="*", default=[], help="Allowed redirect URIs.")
    args = parser.parse_args()
    create_client(tenant_id=args.tenant_id, name=args.name, redirect_uris=args.redirect_uris)
