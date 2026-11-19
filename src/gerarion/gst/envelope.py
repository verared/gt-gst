# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Marca temporal Geroriana firmada (GST, *Gerarion Signed Timestamp*).

AVISO DE BETA: el esquema hash-only de referencia en este módulo es
EDUCATIVO y NO está auditado; no debe usarse para decisiones de seguridad
de producción (ver SECURITY.md / threat-model.md y el gate de
`adapters.make_adapter`).

Estructura del documento GST (JSON), versión 2:

    {
      "v": 2,
      "ctx": "GUS2-TS",
      "alg": "WOTS16-MERKLE-REF-SHA256",   // interoperable con ML-DSA / SLH-DSA
      "ts":  "2031DY-03-08-T-09:30:00-SC-TCJ+0",
      "ins": 64097688600,                   // instante continuo (segundos)
      "day": 741871,                        // índice de día absoluto
      "sig": {"leaf": ..., "sig": [...], "path": [...]},
      "pub": <hex llave pública del árbol>,
      "anchor": { "day": ..., "index": ..., "proof": [...], "root": ... }
    }

Propiedades de la CONSTRUCCIÓN (never "garantías de producto"):

    La firma de este documento (hash-only, sin auditoría) fija el valor de
    la marca a una clave. Para que la marca sea "no removible" haría falta,
    además, un notario externo con réplicas independientes y una confianza
    política previamente fijada: ver docs/threat-model.md. Ninguna frase
    de este módulo debe leerse como "no falsificable en producción".
"""

from __future__ import annotations

import hashlib
import json
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
    """Crea una GST a partir de una entrada de tiempo o un ParsedTimestamp.

    `signer` acepta la interfaz de adaptadores (SigningAdapter) o un
    hashots.WotsMerkleSigner (se envuelve automáticamente).
    """
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
    """Verificación completa: coherencia interna y validez de la firma.

    Devuelve {"ok": bool, "errors": [...], "flags": [...]}.
    """
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
#     "scale": "TCJ",                               # o "TAI" explícito
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

import os as _os
import re as _re

GST_V2_DOMAIN = b"GUS3-GST-V2\x00"
GST_V2_VERSION = "2.0"
GST_V2_POLICY_DEFAULT = "gus-sec-v1"

_EVENT_HASH_RE = _re.compile(r"^sha(256|512):[0-9a-f]{64,128}$")
_NONCE_RE = _re.compile(r"^[0-9a-f]{32}$")


class ReplayGuard:
    """Guardia anti-replay y anti-rollback persistente.

    Registra ``(kid, nonce)`` vistos y el último par ``(seq, ins)`` fiable
    por ``kid``. Rechaza (sin registrar nada del intento):

    - replay: ``(kid, nonce)`` ya visto;
    - rollback de contador: ``seq <=`` último seq confiable del kid;
    - rollback de reloj: ``ins <`` último instante confiable del kid.

    Persistencia opcional en archivo JSON con escritura atómica
    (temporal + os.replace + fsync); sin ruta, solo en memoria.

    FAIL-CLOSED: un archivo de estado corrupto, truncado o de estructura
    ajena ENVENENA la guardia (`_poisoned`): `check_and_record` rechaza
    todo a partir de entonces en lugar de operar como si no hubiera
    historial (eso reiniciaría `seq` desde 0 y habilitaría replay y
    rollback). El operador debe descartar el estado y reemitir con un
    `kid` nuevo.
    """

    def __init__(self, path=None):
        self.path = path
        self._seen: set = set()
        self._last_seq: dict = {}
        self._last_ins: dict = {}
        self._poisoned = False
        if path:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if not isinstance(data, dict):
                    raise ValueError("estado: raiz no es un objeto")
                seen = data.get("seen", [])
                last_seq = data.get("last_seq", {})
                last_ins = data.get("last_ins", {})
                if (
                    not isinstance(seen, list)
                    or not isinstance(last_seq, dict)
                    or not isinstance(last_ins, dict)
                    or not all(
                        isinstance(x, (list, tuple))
                        and len(x) == 2
                        and all(isinstance(t, str) for t in x)
                        for x in seen
                    )
                ):
                    raise ValueError("estado: estructura ajena")
                if not all(
                    isinstance(v, int) and not isinstance(v, bool)
                    for v in list(last_seq.values()) + list(last_ins.values())
                ):
                    raise ValueError("estado: valores no enteros")
                self._seen = {(k, n) for k, n in seen}
                self._last_seq = dict(last_seq)
                self._last_ins = dict(last_ins)
            except FileNotFoundError:
                pass  # sin historial previo: arranque limpio legitimo
            except ValueError:
                # JSON corrupto, truncado o de estructura ajena: fail-closed.
                self._seen, self._last_seq, self._last_ins = set(), {}, {}
                self._poisoned = True

    def check_and_record(self, kid: str, nonce: str, seq: int, ins: int) -> tuple:
        """Devuelve (ok, motivo). Si ok, el estado queda actualizado."""
        if self._poisoned:
            return False, "estado persistido corrupto: guardia en fail-closed"
        if isinstance(seq, bool) or not isinstance(seq, int) or \
                isinstance(ins, bool) or not isinstance(ins, int):
            return False, "seq/ins deben ser enteros"
        key = (kid, nonce)
        if key in self._seen:
            return False, "replay: nonce ya registrado para esta clave"
        last_seq = self._last_seq.get(kid)
        if last_seq is not None and seq <= last_seq:
            return False, f"rollback: seq {seq} <= último confiable {last_seq}"
        last_ins = self._last_ins.get(kid)
        if last_ins is not None and ins < last_ins:
            return False, f"rollback: instante {ins} < último confiable {last_ins}"
        self._seen.add(key)
        self._last_seq[kid] = seq
        self._last_ins[kid] = ins
        if self.path:
            self._save()
        return True, ""

    def _save(self) -> None:
        data = {
            "seen": [list(k) for k in self._seen],
            "last_seq": self._last_seq,
            "last_ins": self._last_ins,
        }
        tmp = f"{self.path}.tmp.{_os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
            fh.flush()
            _os.fsync(fh.fileno())
        _os.replace(tmp, self.path)


def _gst_v2_check_payload(payload: dict) -> list:
    """Valida el esquema del payload GST v2; devuelve la lista de errores."""
    errors = []
    if payload.get("gst_version") != GST_V2_VERSION:
        errors.append(f"gst_version debe ser {GST_V2_VERSION!r}")
    if payload.get("scale") not in ("TCJ", "TAI"):
        errors.append("scale debe ser 'TCJ' o 'TAI' explícito")
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
        date.day_index, parsed.hour, parsed.minute, parsed.second
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


def verify_v2(envelope: dict, guard: "ReplayGuard" = None, **_) -> dict:
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
    if errors:
        return {"ok": False, "errors": errors, "state": "REJECTED"}

    # Coherencia interna de la marca ( igual que v1: la marca manda).
    try:
        parsed = fmt.parse(payload["ts"])
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "errors": [f"formato: {exc}"], "state": "REJECTED"}
    date = cal.from_gerarion(parsed.year, parsed.month, parsed.day)
    instant = cal.instant_from_parts(
        date.day_index, parsed.hour, parsed.minute, parsed.second
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
            return {"ok": False, "errors": [reason], "state": "REJECTED"}
    return {"ok": True, "errors": [], "state": state}
