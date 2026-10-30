"""Per-connection TLS evidence for the pinned identity-only Uvicorn protocol."""

import hashlib
import re
import ssl
from dataclasses import dataclass

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

EXTENSION = "aegis.identity_tls_peer"
REVIEWED_UVICORN = "0.54.0"


def require_compatibility():
    # self.app is a reviewed per-connection H11Protocol field, not an ASGI
    # transport standard. Dependency upgrades must review this adapter explicitly.
    if uvicorn.__version__ != REVIEWED_UVICORN:
        raise RuntimeError("identity_tls_protocol_version_unreviewed")


@dataclass(frozen=True, slots=True)
class ClientCertificate:
    sha256: str
    tls_version: str

    def __post_init__(self):
        if (
            not isinstance(self.sha256, str)
            or not re.fullmatch("[a-f0-9]{64}", self.sha256)
            or not isinstance(self.tls_version, str)
            or self.tls_version not in {"TLSv1.2", "TLSv1.3"}
        ):
            raise ValueError("identity_tls_peer_invalid")

    def headers(self):
        return {
            "X-AEGIS-Client-Cert-SHA256": self.sha256,
            "X-AEGIS-Client-Cert-Policy": "required",
            "X-AEGIS-TLS-Version": self.tls_version,
        }


def certificate(transport):
    """Only an actual SSL context with CERT_REQUIRED and a peer certificate qualifies."""
    try:
        context = transport.get_extra_info("ssl_object")
        if context is None or context.context.verify_mode is not ssl.CERT_REQUIRED:
            return None
        der = context.getpeercert(binary_form=True)
        if type(der) is not bytes or not 0 < len(der) <= 65536:
            return None
        return ClientCertificate(hashlib.sha256(der).hexdigest(), context.version())
    except (ValueError, TypeError, AttributeError, ssl.SSLError):
        return None


class IdentityTLSProtocol(H11Protocol):
    def __init__(self, *args, **kwargs):
        require_compatibility()
        super().__init__(*args, **kwargs)
        self._identity_connection_bound = False

    def connection_made(self, transport):
        if self._identity_connection_bound:
            transport.close()
            raise RuntimeError("identity_tls_protocol_connection_reused")
        super().connection_made(transport)
        self._identity_connection_bound = True
        proof, app = certificate(transport), self.app

        async def with_peer(scope, receive, send):
            # Replace the reserved extension, including on a plaintext/missing
            # peer. Never accept certificate evidence from HTTP headers, shared
            # contextvars or a previous connection's mutable scope.
            if scope["type"] == "http":
                scope = {**scope, "extensions": {**scope.get("extensions", {}), EXTENSION: proof}}
            await app(scope, receive, send)

        # Bind before any HTTP parsing/task scheduling. This also works with
        # eager task factories and pipelining without patching parser internals.
        self.app = with_peer
