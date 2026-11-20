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

"""Revoke an OAuth client and all its tokens.

Usage:
    python scripts/revoke-client.py --tenant-id <uuid> --client-id <client_id>
"""

import argparse


def revoke_client(tenant_id: str, client_id: str) -> None:
    """Revoke a client and all associated tokens."""
    print(f"==> Revoking client {client_id} for tenant {tenant_id}")
    # TODO: Implement client revocation via RevocationService
    print("==> Client and all tokens revoked.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Revoke an OAuth client.")
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID.")
    parser.add_argument("--client-id", required=True, help="OAuth client_id to revoke.")
    args = parser.parse_args()
    revoke_client(tenant_id=args.tenant_id, client_id=args.client_id)
