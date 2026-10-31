"""zProtocol — protocollo di trasporto cifrato e offuscato (prototipo)."""
from .config import Config, derive_psk
from .errors import (
    CryptoError,
    HandshakeError,
    PeerRejected,
    RecordError,
    TruncatedStream,
    ZProtocolError,
)
from .identity import Identity, peer_id
from .record import PaddingPolicy
from .session import Connection, open_connection, serve

__version__ = "0.1.0"

__all__ = [
    "Config",
    "Connection",
    "CryptoError",
    "HandshakeError",
    "Identity",
    "PaddingPolicy",
    "PeerRejected",
    "RecordError",
    "TruncatedStream",
    "ZProtocolError",
    "derive_psk",
    "open_connection",
    "peer_id",
    "serve",
]
