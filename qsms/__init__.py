"""
qsms package

High-level Quantum-Safe Messaging crypto utilities.

Re-exports:
    - CryptoManager (high-level KEM + AES façade)
    - All public symbols from:
        * aes_utils
        * kyber_utils
        * hash_utils
"""

from __future__ import annotations
from typing import TYPE_CHECKING

__all__ = [
    "CryptoManager",
    # Symbols from the utility modules will also be available via lazy loading.
]

# For type checkers/IDE only (doesn't execute at runtime)
if TYPE_CHECKING:
    from .crypto_manager import CryptoManager  # noqa: F401
    from .aes_utils import *   # noqa: F401,F403
    from .kyber_utils import *  # noqa: F401,F403
    from .hash_utils import *   # noqa: F401,F403


def __getattr__(name: str):
    """
    Lazy re-export: resolve attributes on first access to avoid importing
    submodules during package import (prevents runpy warning when running
    `python -m qsms.crypto_manager`).
    """
    import importlib

    # direct mapping for the façade
    if name == "CryptoManager":
        mod = importlib.import_module(".crypto_manager", __name__)
        value = getattr(mod, "CryptoManager")
        globals()[name] = value
        return value

    # try utility modules for any other public symbol
    for mod_name in ("aes_utils", "kyber_utils", "hash_utils"):
        mod = importlib.import_module(f".{mod_name}", __name__)
        if hasattr(mod, name):
            value = getattr(mod, name)
            globals()[name] = value  # cache for subsequent lookups
            # optionally grow __all__ as we discover names
            if name not in __all__:
                __all__.append(name)
            return value

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    # Provide a reasonable dir() without forcing eager imports
    return sorted(set(list(globals().keys()) + __all__))


# Optional: simple version string you can tweak if you like
__version__ = "0.1.0"
