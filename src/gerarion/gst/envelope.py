# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Sobre firmado Gerarion Signed Timestamp (GST v2 normativo + compatibilidad v1).

Entrada pública recomendada: :mod:`gerarion.gst.v2` (``create``, ``verify``,
:class:`~gerarion.gst.v2.VerificationResult`, :class:`~gerarion.gst.trust.KeyRegistry`,
:class:`~gerarion.gst.replay.SQLiteReplayStore`).

Perfil normativo GST v2
-----------------------
Todo sobre ``GST v2`` firma de forma híbrida (**Ed25519 + ML-DSA**) los bytes
exactos ``b"GUS3-GST-V2\\x00" + JCS(payload)`` (RFC 8785, enteros dentro de
IEEE-754 ``binary64`` ``±(2^53 - 1)``), incluyendo el descriptor completo de
algoritmos y claves dentro del payload firmado (protección estructural
**anti-downgrade**):

    {
      "gst_version": "2.0",
      "ts":  "2031DY-03-08-T-09:30:00-SC-TCJ+0",
      "ins": 64097688600,
      "nanos": 0,
      "scale": "TCJ",
      "event_hash": "sha256:<hex>",
      "kid": "...", "issuer": "...",
      "nonce": "<32 hex>", "seq": 1,
      "policy_version": "gus-sec-v1",
      "alg": "HYBRID-ED25519-ML-DSA-65",
      "alg_classical": "ED25519", "alg_pqc": "ML-DSA-65",
      "kid_classical": "...", "kid_pqc": "...",
      "pub_classical": "<hex>", "pub_pqc": "<hex>",
      "sigs": {"alg": "HYBRID-ED25519-ML-DSA-65", "sigs": {"ed25519": "...", "mldsa": "..."}}
    }

Aviso de aseguramiento de producción: la suite ``gt-gst`` y el notario Merkle
requieren una auditoría criptográfica independiente de terceros y custodia de
claves en hardware (TPM/HSM) antes de decisiones críticas de seguridad en
producción (ver ``SECURITY.md`` y ``docs/spec/threat-model.md``).
"""

from __future__ import annotations

import hashlib
import json
import os as _os
import re as _re
import warnings
from dataclasses import asdict, dataclass
from typing import Optional

from . import adapters as _adapters
from ..core import calendar as cal
from ..core import format as fmt
try:
    from ..deprecated import hashots
except ImportError:  # instalación sin el subpaquete deprecated
    hashots = None
from .jcs import JcsError, dumps_bytes as _jcs_bytes
from .replay import ReplayDecision, ReplayGuard, ReplayStore, SQLiteReplayStore

# ===========================================================================
# LEGACY / DEPRECATED (GST v1) — Mantenido únicamente por retrocompatibilidad.
# No forma parte del perfil normativo GST v2. Usa `gerarion.gst.v2.create` y
# `gerarion.gst.v2.verify` (o `create_v2` / `verify_v2`).
# ===========================================================================

ALG_REFERENCE = "WOTS16-MERKLE-REF-SHA256"
SPEC_VERSION = 2


@dataclass
class GtsDocument:
    ts: str
    instant: int
    day: int
    alg: str
    pub: str
    sig: dict
    anchor: Optional[dict] = None
    v: int = SPEC_VERSION
    ctx: str = fmt.CANONICAL_CTX
    nanos: int = 0  # fracción sub-segundo aparte (0..999_999_999)

    def __post_init__(self):
        cal.validate_nanos(self.nanos)

    def to_json(self) -> str:
        data = asdict(self)
        data["ins"] = data.pop("instant")
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "GtsDocument":
        data = json.loads(raw)
        return cls(
            ts=data["ts"],
            instant=int(data["ins"]),
            day=int(data["day"]),
            alg=data["alg"],
            pub=data["pub"],
            sig=data["sig"],
            anchor=data.get("anchor"),
            v=int(data.get("v", 2)),
            ctx=data.get("ctx", fmt.CANONICAL_CTX),
            nanos=int(data.get("nanos", 0)),
        )


def create(raw_or_parsed, signer) -> GtsDocument:
    """LEGACY / DEPRECATED (GST v1): usa ``gerarion.gst.v2.create`` (GST v2)."""
    warnings.warn(
        "create() (GST v1 / GtsDocument) está DEPRECADO; usa "
        "gerarion.gst.v2.create() o create_v2() con HybridSigner (GST v2).",
        DeprecationWarning,
        stacklevel=2,
    )
    adapter = _adapters.make_adapter(signer)
    if isinstance(raw_or_parsed, str):
        parsed = fmt.parse(raw_or_parsed)
    else:
        parsed = raw_or_parsed
    canon = fmt.to_canonical(parsed)
    date = cal.from_gerarion(parsed.year, parsed.month, parsed.day)
    instant = cal.instant_from_parts(date.day_index, parsed.hour, parsed.minute, parsed.second)
    cal.validate_nanos(getattr(parsed, "nanos", 0))
    message = fmt.canonical_bytes(canon, instant)
    sig = adapter.sign_payload(message)
    return GtsDocument(
        ts=canon,
        instant=instant,
        day=date.day_index,
        alg=adapter.alg,
        pub=adapter.public_key_hex,
        sig=sig,
        nanos=getattr(parsed, "nanos", 0),
    )


def verify(doc: GtsDocument) -> dict:
    """LEGACY / DEPRECATED (GST v1): usa ``gerarion.gst.v2.verify`` (GST v2)."""
    warnings.warn(
        "verify() (GST v1 / GtsDocument) está DEPRECADO; usa "
        "gerarion.gst.v2.verify() o verify_v2() para sobres GST v2.",
        DeprecationWarning,
        stacklevel=2,
    )
    errors: list = []
    try:
        parsed = fmt.parse(doc.ts)
    except Exception as exc:  # noqa: BLE001 - superficie de errores del formato
        return {"ok": False, "errors": [f"formato: {exc}"], "flags": []}
    date = cal.from_gerarion(parsed.year, parsed.month, parsed.day)
    instant = cal.instant_from_parts(date.day_index, parsed.hour, parsed.minute, parsed.second)
    if instant != doc.instant:
        errors.append("instante divergente del formato canónico")
    if date.day_index != doc.day:
        errors.append("índice de día divergente del formato canónico")
    if doc.alg != ALG_REFERENCE:
        # Despacho por algoritmo: SLH-DSA (FIPS 205) y ML-DSA (FIPS 204) se
        # verifican vía adaptadores; otros esquemas requieren su biblioteca.
        message = fmt.canonical_bytes(doc.ts, doc.instant, doc.ctx)
        if not isinstance(doc.sig, str):
            errors.append("firma de tipo incompatible con el algoritmo")
            return {"ok": False, "errors": errors, "flags": parsed.flags}
        try:
            if doc.alg.startswith("ML-DSA"):
                ok = _adapters.MlDsaSigner.verify(doc.pub, message, doc.sig, doc.alg)
            else:
                ok = _adapters.SlhDsaSigner.verify(doc.pub, message, doc.sig, doc.alg)
        except ImportError:
            pkg = (
                "el paquete PyPI 'cryptography' (>= 47)"
                if doc.alg.startswith("ML-DSA")
                else "el paquete PyPI 'slh-dsa'"
            )
            return {
                "ok": False,
                "errors": [f"algoritmo {doc.alg} requiere {pkg}"],
                "flags": parsed.flags,
            }
        except Exception as exc:  # noqa: BLE001 - llave/firma malformada
            return {"ok": False, "errors": [f"firma inválida: {exc}"], "flags": parsed.flags}
        if not ok:
            errors.append(f"firma {doc.alg} inválida")
        return {"ok": not errors, "errors": errors, "flags": parsed.flags}
    message = fmt.canonical_bytes(doc.ts, doc.instant, doc.ctx)
    digest = hashots.digest_message(message)
    if not hashots.WotsMerkleSigner.verify(bytes.fromhex(doc.pub), digest, doc.sig):
        errors.append("firma inválida")
    return {"ok": not errors, "errors": errors, "flags": parsed.flags}


def notarize(doc: GtsDocument, notary) -> GtsDocument:
    """Añade el anclaje del notario a una GST firmada.

    La marca entra en la cola del día en curso del notario; tras `seal_day`,
    `notary.inclusion_proof(day, doc.anchor["leaf_index"])` completa el
    anclaje verificable.
    """
    payload = fmt.canonical_bytes(doc.ts, doc.instant, doc.ctx)
    leaf_index = notary.append(payload)
    doc.anchor = {
        "leaf_index": leaf_index,
        "sealed": False,
        "day": notary.current_day,
    }
    return doc


def verify_anchor(doc: GtsDocument, notary) -> dict:
    """Verifica el anclaje de una GST CONTRA EL NOTARIO DE POLÍTICA.

    La raíz y la prueba de inclusión AUTORITATIVAS son las del `notary`
    provisto por el verificador (fuera del documento): la raíz incrustada
    en el documento no es evidencia de nada (cualquiera puede fabricar un
    ancla autoconsistente). Sin `notary` el resultado es fallo explícito
    (GERO_ENOTARY); si el documento además trae una raíz distinta de la del
    notario de política, se marca como divergencia.
    """
    from .notary import verify_inclusion

    if notary is None:
        return {
            "ok": False,
            "errors": [
                "GERO_ENOTARY: se requiere un notario/testigo de política "
                "(fuera del documento) para verificar el anclaje; la raíz "
                "incluida en el documento no es evidencia por sí sola"
            ],
        }
    if not doc.anchor:
        return {"ok": False, "errors": ["sin anclaje de notario"]}
    if not doc.anchor.get("sealed"):
        return {"ok": False, "errors": ["anclaje pendiente de sellado diario"]}
    if "leaf_index" not in doc.anchor:
        return {"ok": False, "errors": ["anclaje incompleto"]}
    payload = fmt.canonical_bytes(doc.ts, doc.instant, doc.ctx)
    leaf = bytes.fromhex(hashlib.sha256(b"\x00" + payload).hexdigest())
    try:
        proof = notary.inclusion_proof(
            int(doc.anchor.get("day", doc.day)), int(doc.anchor["leaf_index"])
        )
    except KeyError as exc:
        return {
            "ok": False,
            "errors": [f"GERO_ENOANCHOR: el notario de política no tiene sellado ese día ({exc})"],
        }
    ok = verify_inclusion(leaf, proof["proof"], proof["index"], bytes.fromhex(proof["root"]))
    errors = [] if ok else ["la marca no está incluida en la raíz del notario de política"]
    if ok and doc.anchor.get("root") and doc.anchor["root"] != proof["root"]:
        errors.append("la raíz incrustada en el documento diverge del notario de política")
    return {"ok": ok, "errors": errors}


# ===========================================================================
# GST v2 — sobre firmado con canonicalización JCS (RFC 8785), vinculación
# obligatoria del evento y metadatos de custodia, con compatibilidad de
# LECTURA de los sellos v1 (documento GtsDocument de arriba, ctx GUS2-TS).
#
# Esquema del sobre (el payload firmado incluye el descriptor de algoritmos):
#
#   {
#     "gst_version": "2.0",
#     "ts":  "2031DY-03-08-T-09:30:00-SC-TCJ+0",   # marca canónica GUS v3.0.0
#     "ins": 64097688600,                           # segundos (int64)
#     "nanos": 0,                                   # 0..999_999_999
#     "scale": "TCJ",                               # coordenada GUS sobre TCJ
#     "event_hash": "sha256:<hex>",                 # VINCULACIÓN OBLIGATORIA
#     "kid": "...", "issuer": "...",
#     "nonce": "<32 hex>", "seq": 42,
#     "policy_version": "gus-sec-v1",
#     "alg": "HYBRID-ED25519-ML-DSA-65",
#     "kid_classical": "...", "kid_pqc": "...",
#     "pub_classical": "<hex>", "pub_pqc": "<hex>"
#   }
#
# La firma cubre EXACTAMENTE  b"GUS3-GST-V2\x00" + JCS(payload)  en UTF-8.
# El descriptor de algoritmos va DENTRO del payload: quitar o degradar la
# rama post-cuántica invalida también la firma clásica (anti-downgrade
# estructural). Hybrida = todo-o-nada: falta o falla una firma → REJECTED.
# ===========================================================================

GST_V2_DOMAIN = b"GUS3-GST-V2\x00"
GST_V2_VERSION = "2.0"
GST_V2_POLICY_DEFAULT = "gus-sec-v1"

_EVENT_HASH_RE = _re.compile(r"(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})\Z")
_NONCE_RE = _re.compile(r"^[0-9a-f]{32}$")


def _matches_event_hash(actual, expected) -> bool:
    return (isinstance(actual, str) and isinstance(expected, str)
            and bool(_EVENT_HASH_RE.fullmatch(actual)) and actual == expected)


def _gst_v2_check_payload(payload: dict) -> list:
    """Valida el esquema del payload GST v2; devuelve la lista de errores."""
    errors = []
    if payload.get("gst_version") != GST_V2_VERSION:
        errors.append(f"gst_version debe ser {GST_V2_VERSION!r}")
    if payload.get("scale") != "TCJ":
        errors.append("scale debe ser 'TCJ'; no se admite relabeling a TAI")
    eh = payload.get("event_hash")
    if not isinstance(eh, str) or not _EVENT_HASH_RE.match(eh):
        errors.append(
            "event_hash obligatorio con forma 'sha256:<hex>' o 'sha512:<hex>'"
        )
    for field in ("kid", "issuer", "policy_version"):
        if not isinstance(payload.get(field), str) or not payload.get(field):
            errors.append(f"{field} es obligatorio (metadatos de custodia)")
    if not isinstance(payload.get("nonce"), str) or not _NONCE_RE.match(
        payload.get("nonce", "")
    ):
        errors.append("nonce debe ser hex de 16 bytes (32 caracteres)")
    seq = payload.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        errors.append("seq debe ser un entero monotónico >= 0")
    ins = payload.get("ins")
    if isinstance(ins, bool) or not isinstance(ins, int):
        errors.append("ins debe ser el instante entero (segundos)")
    nanos = payload.get("nanos")
    try:
        cal.validate_nanos(nanos)
    except Exception:  # noqa: BLE001 - rango inválido = error del sobre
        errors.append(f"nanos fuera de rango 0..{cal.NANOS_MAX}")
    alg = payload.get("alg", "")
    if not isinstance(alg, str) or not alg.startswith("HYBRID-ED25519-ML-DSA-"):
        errors.append("alg debe ser un híbrido HYBRID-ED25519-ML-DSA-*")
    for field in ("kid_classical", "kid_pqc", "pub_classical", "pub_pqc"):
        if not isinstance(payload.get(field), str) or not payload.get(field):
            errors.append(f"{field} es obligatorio en el descriptor híbrido")
    return errors


def gst_v2_message(payload: dict) -> bytes:
    """Bytes exactos que se firman: dominio || JCS(payload)."""
    return GST_V2_DOMAIN + _jcs_bytes(payload)


def create_v2(
    raw_or_parsed,
    signer: "_adapters.HybridSigner",
    *,
    event_hash: str,
    kid: str,
    issuer: str,
    seq: int,
    nonce: str = None,
    scale: str = "TCJ",
    policy_version: str = GST_V2_POLICY_DEFAULT,
) -> dict:
    """Emite un sobre GST v2 firmado de forma híbrida (Ed25519 + ML-DSA).

    `signer` debe ser un HybridSigner (la firma híbrida es obligatoria en
    v2: el esquema no emite sellos de una sola rama). `nonce` por defecto
    es aleatorio criptográfico (os.urandom(16).hex()).
    """
    if not isinstance(signer, _adapters.HybridSigner):
        raise TypeError("GST v2 exige un HybridSigner (Ed25519 + ML-DSA)")
    if scale != "TCJ":
        raise ValueError("GST v2 solo admite la escala TCJ")
    if not isinstance(event_hash, str) or not _EVENT_HASH_RE.match(event_hash):
        raise ValueError(
            "event_hash obligatorio con forma 'sha256:<hex>' o 'sha512:<hex>'"
        )
    if nonce is None:
        nonce = _os.urandom(16).hex()
    if not _NONCE_RE.match(nonce):
        raise ValueError("nonce debe ser hex de 16 bytes (32 caracteres)")

    if isinstance(raw_or_parsed, str):
        parsed = fmt.parse(raw_or_parsed)
    else:
        parsed = raw_or_parsed
    canon = fmt.to_canonical(parsed)
    date = cal.from_gerarion(parsed.year, parsed.month, parsed.day)
    instant = cal.instant_from_parts(
        date.day_index, parsed.hour, parsed.minute, parsed.second, parsed.offset_seconds
    )
    nanos = getattr(parsed, "nanos", 0)
    cal.validate_nanos(nanos)

    payload = {
        "gst_version": GST_V2_VERSION,
        "ts": canon,
        "ins": instant,
        "nanos": nanos,
        "scale": scale,
        "event_hash": event_hash,
        "kid": kid,
        "issuer": issuer,
        "nonce": nonce,
        "seq": seq,
        "policy_version": policy_version,
        **signer.descriptor(),
        "pub_classical": signer.public_key_hex,
        "pub_pqc": signer.public_key_pqc_hex,
    }
    message = gst_v2_message(payload)
    envelope = dict(payload)
    # Blob de firma completo: algoritmo declarado + par de firmas sobre los
    # MISMOS bytes (HybridVerifier exige el par y la coherencia del alg).
    envelope["sigs"] = signer.sign_payload(message)
    return envelope


def verify_v2(envelope: dict, guard: "ReplayGuard" = None, *, expected_event_hash: str) -> dict:
    """Verificación GST v2 completa: esquema, firma dual y guardia anti-replay.

    Devuelve {"ok": bool, "errors": [...], "state": "..."}; con guard, un
    sobre válido se registra y un replay/rollback queda RECHAZADO.
    Los sellos v1 (GtsDocument) siguen verificándose con `verify()`:
    esta función NO los acepta (versiones y dominios distintos).
    """
    errors: list = []
    if not isinstance(envelope, dict):
        return {"ok": False, "errors": ["sobre no objeto JSON"], "state": "REJECTED"}
    # El sobre llevado al alambre incluye 'sigs'; el payload firmado NO.
    if "sigs" not in envelope:
        return {
            "ok": False,
            "errors": ["falta el bloque de firmas 'sigs'"],
            "state": "REJECTED",
        }
    payload = {k: v for k, v in envelope.items() if k != "sigs"}
    errors.extend(_gst_v2_check_payload(payload))
    if not _matches_event_hash(payload.get("event_hash"), expected_event_hash):
        errors.append("event_hash no coincide con el digest del artefacto esperado")
    if errors:
        return {"ok": False, "errors": errors, "state": "REJECTED"}

    # Coherencia interna de la marca ( igual que v1: la marca manda).
    try:
        parsed = fmt.parse(payload["ts"])
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "errors": [f"formato: {exc}"], "state": "REJECTED"}
    date = cal.from_gerarion(parsed.year, parsed.month, parsed.day)
    instant = cal.instant_from_parts(
        date.day_index, parsed.hour, parsed.minute, parsed.second, parsed.offset_seconds
    )
    if instant != payload["ins"]:
        errors.append("instante divergente del formato canónico")
    # La marca debe estar en forma canónica (sin fracción): la precisión
    # sub-segundo viaja SOLAMENTE en el campo separado `nanos`, protegido
    # por la firma (el formato canónico nunca emite la fracción).
    if fmt.to_canonical(parsed) != payload["ts"]:
        errors.append("la marca no está en forma canónica")
    if errors:
        return {"ok": False, "errors": errors, "state": "REJECTED"}

    message = gst_v2_message(payload)
    expected_alg = payload["alg"]
    ok = _adapters.HybridVerifier.verify(
        payload["pub_classical"],
        payload["pub_pqc"],
        message,
        envelope["sigs"],
        expected_alg,
    )
    if not ok:
        errors.append("firma híbrida inválida (ambas ramas deben verificar)")
        return {"ok": False, "errors": errors, "state": "REJECTED"}

    state = "VALID"
    if guard is not None:
        ok_guard, reason = guard.check_and_record(
            payload["kid"], payload["nonce"], payload["seq"], payload["ins"]
        )
        if not ok_guard:
            return {
                "ok": False,
                "errors": [reason],
                "state": "REJECTED",
                "replay_checked": True,
            }
        return {"ok": True, "errors": [], "state": state, "replay_checked": True}
    return {"ok": True, "errors": [], "state": state, "replay_checked": False}
