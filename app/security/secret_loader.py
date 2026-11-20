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
