"""Eccezioni di zProtocol."""


class ZProtocolError(Exception):
    """Base di tutti gli errori del protocollo."""


class CryptoError(ZProtocolError):
    """Autenticazione AEAD fallita o operazione crittografica non valida."""


class HandshakeError(ZProtocolError):
    """Handshake non valido, non autenticato o interrotto."""


class PeerRejected(HandshakeError):
    """La chiave pubblica del peer non è stata accettata dalla policy locale."""


class RecordError(ZProtocolError):
    """Record malformato, manomesso, riordinato o ripetuto."""


class TruncatedStream(RecordError):
    """Il flusso è terminato senza un record CLOSE autenticato (possibile troncamento)."""
