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

# Import the main façade
from .crypto_manager import CryptoManager

# Import submodules so we can build __all__ from their public exports
from . import aes_utils as _aes_utils
from . import kyber_utils as _kyber_utils
from . import hash_utils as _hash_utils

# Re-export everything those modules mark as public
from .aes_utils import *   # noqa: F401,F403
from .kyber_utils import *  # noqa: F401,F403
from .hash_utils import *   # noqa: F401,F403

# Package-level public API
__all__ = (
    ["CryptoManager"]
    + list(getattr(_aes_utils, "__all__", []))
    + list(getattr(_kyber_utils, "__all__", []))
    + list(getattr(_hash_utils, "__all__", []))
)

# Optional: simple version string you can tweak if you like
__version__ = "0.1.0"
