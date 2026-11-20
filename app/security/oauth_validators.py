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

"""OAuth validators — parameter and grant validation helpers."""

from app.core.exceptions import AuthError


def validate_redirect_uri(uri: str, allowed_uris: list[str]) -> None:
    """Ensure the redirect URI matches a registered URI."""
    if uri not in allowed_uris:
        raise AuthError(status_code=400, detail="Invalid redirect_uri.")


def validate_scope(requested: str, allowed: str) -> list[str]:
    """Return the intersection of requested and allowed scopes."""
    requested_set = set(requested.split())
    allowed_set = set(allowed.split())
    valid = requested_set & allowed_set
    if not valid:
        raise AuthError(status_code=400, detail="No valid scopes requested.")
    return sorted(valid)


def validate_grant_type(grant_type: str, allowed_types: list[str]) -> None:
    """Ensure the grant type is permitted for the client."""
    if grant_type not in allowed_types:
        raise AuthError(status_code=400, detail=f"Unsupported grant_type: {grant_type}")
