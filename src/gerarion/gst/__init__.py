# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Subpaquete ``gerarion.gst`` — sellado criptográfico de eventos (GST v2).

Entrada pública principal recomendada: :mod:`gerarion.gst.v2`.
"""

from __future__ import annotations

from . import adapters, envelope, jcs, notary, notary_cluster, replay, trust, v2
from .adapters import (
    HYBRID_ALG_DEFAULT,
    Ed25519Signer,
    HybridSigner,
    HybridVerifier,
    MlDsaSigner,
)
from .envelope import (
    GST_V2_DOMAIN,
    GST_V2_POLICY_DEFAULT,
    GST_V2_VERSION,
    GtsDocument,
    create,
    create_v2,
    gst_v2_message,
    notarize,
    verify,
    verify_anchor,
    verify_v2,
)
from .replay import ReplayDecision, ReplayGuard, ReplayStore, SQLiteReplayStore
from .trust import KeyRegistry, KeyResolution, TrustedKeyRecord
from .v2 import (
    CryptoLevel,
    CryptographicValidity,
    IdentityLevel,
    IdentityPolicyValidity,
    TemporalAssurance,
    TemporalLevel,
    VerificationResult,
)

__all__ = [
    "v2",
    "trust",
    "replay",
    "envelope",
    "adapters",
    "jcs",
    "notary",
    "notary_cluster",
    "KeyRegistry",
    "TrustedKeyRecord",
    "KeyResolution",
    "ReplayStore",
    "SQLiteReplayStore",
    "ReplayGuard",
    "ReplayDecision",
    "VerificationResult",
    "CryptographicValidity",
    "IdentityPolicyValidity",
    "TemporalAssurance",
    "CryptoLevel",
    "IdentityLevel",
    "TemporalLevel",
    "HybridSigner",
    "HybridVerifier",
    "Ed25519Signer",
    "MlDsaSigner",
    "HYBRID_ALG_DEFAULT",
    "GST_V2_DOMAIN",
    "GST_V2_VERSION",
    "GST_V2_POLICY_DEFAULT",
    "create_v2",
    "verify_v2",
    "gst_v2_message",
    "GtsDocument",
    "create",
    "verify",
    "notarize",
    "verify_anchor",
]
