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

"""Secret loader — retrieves secrets from vault or environment variables."""

import os


def load_secret(name: str, *, fallback: str | None = None) -> str:
    """Load a secret from a file path (Kubernetes-style) or environment variable.

    Lookup order:
    1. File at path specified by ``{name}_FILE`` environment variable
    2. Environment variable ``{name}``
    3. Fallback value
    """
    file_env = f"{name}_FILE"
    file_path = os.environ.get(file_env)
    if file_path and os.path.isfile(file_path):
        with open(file_path, encoding="utf-8") as f:
            return f.read().strip()

    value = os.environ.get(name)
    if value is not None:
        return value

    if fallback is not None:
        return fallback

    raise RuntimeError(f"Secret '{name}' not found in environment or file.")
