# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Entrada pública principal y recomendada de GST v2 (``gerarion.gst.v2``).

Separa explícitamente la verificación de un sobre ``GST v2`` en tres niveles
ortogonales con códigos de razón auditables:

1. **Nivel 1 — ``crypto`` (:class:`CryptographicValidity`):** validez
   matemática y estructural del sobre (JCS RFC 8785, ``event_hash``,
   vinculación anti-downgrade del descriptor híbrido y verificación dual
   Ed25519 + ML-DSA sobre ``b"GUS3-GST-V2\\x00" + JCS(payload)``).
2. **Nivel 2 — ``identity`` (:class:`IdentityPolicyValidity`):** autorización
   de la clave pública para ``(issuer, kid)`` en el instante firmado contra
   un :class:`KeyRegistry` (detección de claves suplantadas/autofirmadas,
   rotación histórica, expiración y revocación) y protección transaccional
   anti-replay / anti-rollback contra un :class:`ReplayStore`
   (:class:`SQLiteReplayStore` o :class:`ReplayGuard`).
3. **Nivel 3 — ``temporal`` (:class:`TemporalAssurance`):** calidad y estado
   de confianza del reloj (``VERIFIED``, ``HOLDOVER``, ``UNVERIFIED``,
   ``REJECTED`` o ``UNKNOWN`` cuando no se aporta una lectura verificada de
   ``gt-gts``).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable, Optional

from ..core import calendar as cal
from ..core import format as fmt
from . import adapters as _adapters
from . import envelope as _env
from .jcs import JcsError, dumps_bytes as _jcs_bytes
from .replay import ReplayDecision, ReplayGuard, ReplayStore, SQLiteReplayStore
from .trust import KeyRegistry, KeyResolution, TrustedKeyRecord

__all__ = [
    "create",
    "verify",
    "VerificationResult",
    "CryptographicValidity",
    "IdentityPolicyValidity",
    "TemporalAssurance",
    "CryptoLevel",
    "IdentityLevel",
    "TemporalLevel",
    "KeyRegistry",
    "TrustedKeyRecord",
    "KeyResolution",
    "ReplayStore",
    "SQLiteReplayStore",
    "ReplayGuard",
    "ReplayDecision",
]


@dataclass(frozen=True)
class CryptographicValidity:
    """Nivel 1: validez criptográfica y estructural del sobre GST v2."""

    valid: bool
    algorithm: str
    jcs_valid: bool
    event_hash_valid: bool
    anti_downgrade_ok: bool
    reason: str


@dataclass(frozen=True)
class IdentityPolicyValidity:
    """Nivel 2: identidad del emisor, vigencia de clave y estado anti-replay."""

    valid: bool
    trusted_issuer: bool
    key_status: str     # ACTIVE | HISTORICAL | UNKNOWN | MISMATCH | REVOKED | EXPIRED | UNCHECKED
    replay_checked: bool
    replay_status: str  # OK | REPLAY | SEQ_ROLLBACK | SKIPPED
    reason: str


@dataclass(frozen=True)
class TemporalAssurance:
    """Nivel 3: aseguramiento temporal y contexto del reloj."""

    clock_state: str  # VERIFIED | HOLDOVER | UNVERIFIED | REJECTED | UNKNOWN
    clock_source: Optional[str] = None
    clock_uncertainty_ns: Optional[int] = None
    event_time: Optional[str] = None
    recorded_at: Optional[str] = None
    signed_at: Optional[str] = None


# Alias cortos expuestos en la API pública
CryptoLevel = CryptographicValidity
IdentityLevel = IdentityPolicyValidity
TemporalLevel = TemporalAssurance


@dataclass(frozen=True)
class VerificationResult:
    """Resultado estructurado; una lectura externa por sí sola no ancla un sello."""

    crypto: CryptographicValidity
    identity: IdentityPolicyValidity
    temporal: TemporalAssurance
    anchor_verified: bool = False

    @property
    def sealed(self) -> bool:
        return self.crypto.valid and self.identity.valid

    @property
    def anchored(self) -> bool:
        return self.sealed and self.temporal.clock_state == "VERIFIED" and self.anchor_verified

    @property
    def overall_trusted(self) -> bool:
        """True solo para un sello corroborado bajo la política de anclaje."""
        return self.anchored

    def to_dict(self) -> dict:
        data = asdict(self)
        data["sealed"] = self.sealed
        data["anchored"] = self.anchored
        data["overall_trusted"] = self.overall_trusted
        return data


def create(
    raw_or_parsed,
    signer: "_adapters.HybridSigner",
    *,
    event_hash: str,
    kid: str,
    issuer: str,
    seq: int,
    nonce: Optional[str] = None,
    scale: str = "TCJ",
    policy_version: str = _env.GST_V2_POLICY_DEFAULT,
    event_time: Optional[str] = None,
    recorded_at: Optional[str] = None,
) -> dict:
    """Emite un sobre GST v2 firmado con Ed25519 + ML-DSA sobre RFC 8785 (JCS)."""
    env = _env.create_v2(
        raw_or_parsed,
        signer,
        event_hash=event_hash,
        kid=kid,
        issuer=issuer,
        seq=seq,
        nonce=nonce,
        scale=scale,
        policy_version=policy_version,
    )
    if event_time is not None or recorded_at is not None:
        payload = {k: v for k, v in env.items() if k != "sigs"}
        if event_time is not None:
            payload["event_time"] = str(event_time)
        if recorded_at is not None:
            payload["recorded_at"] = str(recorded_at)
        message = _env.gst_v2_message(payload)
        env = dict(payload)
        env["sigs"] = signer.sign_payload(message)
    return env


def _extract_temporal(
    payload: dict,
    clock_reading: Optional[Any],
) -> TemporalAssurance:
    signed_at = payload.get("ts") if isinstance(payload.get("ts"), str) else None
    event_time = (
        payload.get("event_time")
        if isinstance(payload.get("event_time"), str)
        else signed_at
    )
    recorded_at = (
        payload.get("recorded_at")
        if isinstance(payload.get("recorded_at"), str)
        else signed_at
    )

    if clock_reading is None:
        return TemporalAssurance(
            clock_state="UNKNOWN",
            clock_source=None,
            clock_uncertainty_ns=None,
            event_time=event_time,
            recorded_at=recorded_at,
            signed_at=signed_at,
        )

    if isinstance(clock_reading, dict):
        raw_state = clock_reading.get("clock_state") or clock_reading.get("state")
        source = clock_reading.get("clock_source") or clock_reading.get("source_id")
        unc = clock_reading.get("clock_uncertainty_ns", clock_reading.get("uncertainty_ns"))
    else:
        raw_state = getattr(clock_reading, "state", None)
        if hasattr(raw_state, "value"):
            raw_state = raw_state.value
        source = getattr(clock_reading, "source_id", None)
        unc = getattr(clock_reading, "uncertainty_ns", None)

    allowed_states = {"VERIFIED", "HOLDOVER", "UNVERIFIED", "REJECTED", "UNKNOWN"}
    state_str = str(raw_state).upper() if raw_state is not None else "UNKNOWN"
    if state_str not in allowed_states:
        state_str = "UNKNOWN"

    return TemporalAssurance(
        clock_state=state_str,
        clock_source=str(source) if source else None,
        clock_uncertainty_ns=int(unc) if isinstance(unc, int) and not isinstance(unc, bool) else None,
        event_time=event_time,
        recorded_at=recorded_at,
        signed_at=signed_at,
    )


def _evaluate_crypto(envelope: Any, expected_event_hash: str) -> tuple[CryptographicValidity, Optional[dict]]:
    if not isinstance(envelope, dict):
        return (
            CryptographicValidity(
                valid=False,
                algorithm="",
                jcs_valid=False,
                event_hash_valid=False,
                anti_downgrade_ok=False,
                reason="INVALID_ENVELOPE: el sobre no es un objeto dict",
            ),
            None,
        )

    payload = {k: v for k, v in envelope.items() if k != "sigs"}
    alg = str(payload.get("alg") or "")

    # 1. Validación JCS estricta (incluye límite ±(2^53-1))
    try:
        _jcs_bytes(payload)
        jcs_valid = True
    except (JcsError, Exception) as exc:  # noqa: BLE001
        return (
            CryptographicValidity(
                valid=False,
                algorithm=alg,
                jcs_valid=False,
                event_hash_valid=False,
                anti_downgrade_ok=False,
                reason=f"JCS_INVALID: {exc}",
            ),
            payload,
        )

    # 2. Validación de event_hash
    eh = payload.get("event_hash")
    event_hash_valid = _env._matches_event_hash(eh, expected_event_hash)
    if not event_hash_valid:
        return CryptographicValidity(False, alg, jcs_valid, False, False,
                                     "INVALID_EVENT_HASH: digest ausente, inválido o divergente"), payload

    # 3. Validación anti-downgrade del descriptor híbrido
    sigs_blob = envelope.get("sigs")
    has_hybrid_fields = all(
        isinstance(payload.get(f), str) and bool(payload.get(f))
        for f in ("alg", "alg_classical", "alg_pqc", "kid_classical", "kid_pqc", "pub_classical", "pub_pqc")
    )
    sigs_dict = sigs_blob.get("sigs") if isinstance(sigs_blob, dict) else None
    anti_downgrade_ok = bool(
        has_hybrid_fields
        and alg.startswith("HYBRID-ED25519-ML-DSA-")
        and isinstance(sigs_blob, dict)
        and sigs_blob.get("alg") == alg
        and isinstance(sigs_dict, dict)
        and isinstance(sigs_dict.get("ed25519"), str)
        and isinstance(sigs_dict.get("mldsa"), str)
        and bool(sigs_dict.get("ed25519"))
        and bool(sigs_dict.get("mldsa"))
    )

    if "sigs" not in envelope:
        return (
            CryptographicValidity(
                valid=False,
                algorithm=alg,
                jcs_valid=jcs_valid,
                event_hash_valid=event_hash_valid,
                anti_downgrade_ok=False,
                reason="MISSING_SIGS: falta el bloque de firmas 'sigs'",
            ),
            payload,
        )

    schema_errors = _env._gst_v2_check_payload(payload)
    if schema_errors:
        code = (
            "INVALID_EVENT_HASH"
            if not event_hash_valid
            else ("DOWNGRADE_DETECTED" if not anti_downgrade_ok else "SCHEMA_INVALID")
        )
        return (
            CryptographicValidity(
                valid=False,
                algorithm=alg,
                jcs_valid=jcs_valid,
                event_hash_valid=event_hash_valid,
                anti_downgrade_ok=anti_downgrade_ok,
                reason=f"{code}: {'; '.join(schema_errors)}",
            ),
            payload,
        )

    # 4. Coherencia temporal interna del sello GUS
    try:
        parsed = fmt.parse(payload["ts"])
        date = cal.from_gerarion(parsed.year, parsed.month, parsed.day)
        instant = cal.instant_from_parts(
            date.day_index, parsed.hour, parsed.minute, parsed.second, parsed.offset_seconds
        )
    except Exception as exc:  # noqa: BLE001
        return (
            CryptographicValidity(
                valid=False,
                algorithm=alg,
                jcs_valid=jcs_valid,
                event_hash_valid=event_hash_valid,
                anti_downgrade_ok=anti_downgrade_ok,
                reason=f"TIMESTAMP_INVALID: {exc}",
            ),
            payload,
        )

    if instant != payload["ins"] or fmt.to_canonical(parsed) != payload["ts"]:
        return (
            CryptographicValidity(
                valid=False,
                algorithm=alg,
                jcs_valid=jcs_valid,
                event_hash_valid=event_hash_valid,
                anti_downgrade_ok=anti_downgrade_ok,
                reason="TIMESTAMP_MISMATCH: instante o formato canónico divergente",
            ),
            payload,
        )

    if not anti_downgrade_ok:
        return (
            CryptographicValidity(
                valid=False,
                algorithm=alg,
                jcs_valid=jcs_valid,
                event_hash_valid=event_hash_valid,
                anti_downgrade_ok=False,
                reason="DOWNGRADE_DETECTED: descriptor híbrido o par de firmas incompleto",
            ),
            payload,
        )

    # 5. Verificación matemática dual Ed25519 + ML-DSA
    message = _env.gst_v2_message(payload)
    ok_sig = _adapters.HybridVerifier.verify(
        payload["pub_classical"],
        payload["pub_pqc"],
        message,
        sigs_blob,
        alg,
    )
    if not ok_sig:
        return (
            CryptographicValidity(
                valid=False,
                algorithm=alg,
                jcs_valid=jcs_valid,
                event_hash_valid=event_hash_valid,
                anti_downgrade_ok=anti_downgrade_ok,
                reason="SIGNATURE_INVALID: firma híbrida inválida (ambas ramas deben verificar)",
            ),
            payload,
        )

    return (
        CryptographicValidity(
            valid=True,
            algorithm=alg,
            jcs_valid=True,
            event_hash_valid=True,
            anti_downgrade_ok=True,
            reason="CRYPTO_OK: firma híbrida Ed25519 + ML-DSA y JCS verificados",
        ),
        payload,
    )


def verify(
    envelope: dict,
    *,
    expected_event_hash: str,
    trust_store: Optional[KeyRegistry] = None,
    replay_store: Optional[ReplayStore] = None,
    guard: Optional[ReplayStore] = None,
    clock_reading: Optional[Any] = None,
    verify_temporal_anchor: Optional[Callable[[bytes, TemporalAssurance], bool]] = None,
    allow_unchecked_replay: bool = False,
    required_scope: Optional[str] = None,
) -> VerificationResult:
    """Verifica un sobre GST v2 devolviendo un :class:`VerificationResult` en 3 niveles.

    Política *fail-closed*:
    - Si ``trust_store`` es ``None``, ``identity.trusted_issuer`` es ``False`` y
      ``identity.key_status == "UNCHECKED"``.
    - Si ``replay_store`` (o ``guard``) es ``None``, ``identity.replay_checked``
      es ``False``, ``identity.replay_status == "SKIPPED"`` e
      ``identity.valid`` es ``False`` salvo que se pase explícitamente
      ``allow_unchecked_replay=True``.
    """
    # El callback de política confiable debe vincular evidencia verificada a
    # estos bytes exactos del sobre (incluidas las firmas) y a la lectura.
    active_replay_store = replay_store if replay_store is not None else guard
    crypto, payload = _evaluate_crypto(envelope, expected_event_hash)
    temporal = _extract_temporal(payload or {}, clock_reading)

    if not crypto.valid or payload is None:
        return VerificationResult(
            crypto=crypto,
            identity=IdentityPolicyValidity(
                valid=False,
                trusted_issuer=False,
                key_status="UNCHECKED",
                replay_checked=False,
                replay_status="SKIPPED",
                reason="CRYPTO_FAILED: no se evalúa identidad sobre firma inválida",
            ),
            temporal=temporal,
        )

    # Nivel 2a: evaluación de KeyRegistry
    if trust_store is None:
        trusted_issuer = False
        key_status = "UNCHECKED"
        trust_reason = "TRUST_UNCHECKED: no se suministró KeyRegistry (trust_store=None)"
    else:
        resolution = trust_store.resolve(
            issuer=payload["issuer"],
            kid=payload["kid"],
            at_time=payload["ins"],
            pub_classical=payload["pub_classical"],
            pub_pqc=payload["pub_pqc"],
            required_scope=required_scope,
        )
        trusted_issuer = resolution.trusted
        key_status = resolution.key_status
        trust_reason = resolution.reason

    # Nivel 2b: evaluación de ReplayStore
    # Importante: solo se registra el nonce/seq si la clave es confiable (o si
    # trust_store no fue provisto y se está probando replay aislado), evitando
    # que un atacante con clave falsa contamine el estado de seq del emisor real.
    can_record_replay = (trust_store is None) or trusted_issuer

    if active_replay_store is None:
        replay_checked = False
        replay_status = "SKIPPED"
        replay_ok = bool(allow_unchecked_replay)
        replay_reason = (
            "REPLAY_SKIPPED_ALLOWED: replay no verificado (allow_unchecked_replay=True)"
            if allow_unchecked_replay
            else "REPLAY_UNCHECKED: no se suministró ReplayStore (fail-closed)"
        )
    elif not can_record_replay:
        replay_checked = False
        replay_status = "SKIPPED"
        replay_ok = False
        replay_reason = "REPLAY_SKIPPED_UNTRUSTED_KEY: clave no autorizada; no se muta ReplayStore"
    else:
        decision = active_replay_store.check_and_record(
            payload["issuer"],
            payload["kid"],
            payload["seq"],
            payload["nonce"],
            payload["ins"],
        )
        replay_checked = True
        if isinstance(decision, ReplayDecision):
            replay_ok = decision.ok
            replay_status = decision.status
            replay_reason = decision.reason or "REPLAY_OK"
        else:
            ok_flag, msg = decision
            replay_ok = bool(ok_flag)
            replay_status = (
                "OK"
                if replay_ok
                else ("REPLAY" if "replay" in str(msg).lower() else "SEQ_ROLLBACK")
            )
            replay_reason = str(msg) or ("REPLAY_OK" if replay_ok else "REPLAY_REJECTED")

    identity_valid = bool(trusted_issuer and replay_ok)
    anchor_verified = False
    if identity_valid and temporal.clock_state == "VERIFIED" and verify_temporal_anchor is not None:
        try:
            anchor_verified = verify_temporal_anchor(_jcs_bytes(envelope), temporal) is True
        except Exception:
            pass  # unavailable or invalid temporal evidence cannot promote a seal
    if not trusted_issuer:
        combined_reason = trust_reason
    elif not replay_ok:
        combined_reason = f"{trust_reason}; {replay_reason}"
    else:
        combined_reason = f"{trust_reason}; {replay_reason}"

    return VerificationResult(
        crypto=crypto,
        identity=IdentityPolicyValidity(
            valid=identity_valid,
            trusted_issuer=trusted_issuer,
            key_status=key_status,
            replay_checked=replay_checked,
            replay_status=replay_status,
            reason=combined_reason,
        ),
        temporal=temporal,
        anchor_verified=anchor_verified,
    )
