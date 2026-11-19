# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Registro de confianza de claves para GST v2 (stdlib pura).

Vincula ``(issuer, kid)`` con las claves públicas autorizadas
(``pub_classical`` Ed25519 y ``pub_pqc`` ML-DSA), su ventana de vigencia
temporal sobre coordenadas TCJ (``valid_from``, ``valid_until``), su estado
de revocación (``revoked_at``, ``revocation_reason``) y alcances opcionales
(``scopes``).

Cierra el hueco entre validez matemática (Nivel 1: las firmas verifican
contra las claves públicas incrustadas en el propio sobre) y validez de
identidad/política (Nivel 2: esas claves públicas pertenecen realmente al
``(issuer, kid)`` declarado y estaban vigentes en el instante firmado).
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

from ..core import calendar as cal
from ..core import format as fmt

__all__ = [
    "TrustedKeyRecord",
    "KeyResolution",
    "KeyRegistry",
]


def _coerce_instant(value: Optional[Union[int, str]]) -> Optional[int]:
    """Convierte un instante entero (segundos TCJ) o sello GUS a int."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise TypeError("instante temporal no puede ser booleano")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        parsed = fmt.parse(value)
        gd = cal.from_gerarion(parsed.year, parsed.month, parsed.day)
        return cal.instant_from_parts(
            gd.day_index, parsed.hour, parsed.minute, parsed.second
        )
    raise TypeError(f"tipo de instante no soportado: {type(value).__name__}")


@dataclass(frozen=True)
class TrustedKeyRecord:
    """Registro inmutable de una clave híbrida autorizada para (issuer, kid)."""

    issuer: str
    kid: str
    pub_classical: str
    pub_pqc: str
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None
    revoked_at: Optional[int] = None
    revocation_reason: Optional[str] = None
    scopes: Tuple[str, ...] = ()
    historical: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer.strip():
            raise ValueError("issuer es obligatorio en TrustedKeyRecord")
        if not isinstance(self.kid, str) or not self.kid.strip():
            raise ValueError("kid es obligatorio en TrustedKeyRecord")
        if not isinstance(self.pub_classical, str) or not self.pub_classical.strip():
            raise ValueError("pub_classical es obligatorio en TrustedKeyRecord")
        if not isinstance(self.pub_pqc, str) or not self.pub_pqc.strip():
            raise ValueError("pub_pqc es obligatorio en TrustedKeyRecord")
        vf = _coerce_instant(self.valid_from)
        vu = _coerce_instant(self.valid_until)
        ra = _coerce_instant(self.revoked_at)
        if vf is not None and vu is not None and vu < vf:
            raise ValueError("valid_until no puede ser anterior a valid_from")
        object.__setattr__(self, "pub_classical", self.pub_classical.strip().lower())
        object.__setattr__(self, "pub_pqc", self.pub_pqc.strip().lower())
        object.__setattr__(self, "valid_from", vf)
        object.__setattr__(self, "valid_until", vu)
        object.__setattr__(self, "revoked_at", ra)
        object.__setattr__(self, "scopes", tuple(self.scopes or ()))

    def to_dict(self) -> dict:
        return {
            "issuer": self.issuer,
            "kid": self.kid,
            "pub_classical": self.pub_classical,
            "pub_pqc": self.pub_pqc,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
            "scopes": list(self.scopes),
            "historical": self.historical,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TrustedKeyRecord":
        if not isinstance(data, dict):
            raise ValueError("TrustedKeyRecord requiere un objeto dict")
        return cls(
            issuer=data["issuer"],
            kid=data["kid"],
            pub_classical=data["pub_classical"],
            pub_pqc=data["pub_pqc"],
            valid_from=data.get("valid_from"),
            valid_until=data.get("valid_until"),
            revoked_at=data.get("revoked_at"),
            revocation_reason=data.get("revocation_reason"),
            scopes=tuple(data.get("scopes") or ()),
            historical=bool(data.get("historical", False)),
        )


@dataclass(frozen=True)
class KeyResolution:
    """Resultado de evaluar una clave del sobre contra el KeyRegistry."""

    trusted: bool
    key_status: str  # ACTIVE | HISTORICAL | UNKNOWN | MISMATCH | REVOKED | EXPIRED
    code: str        # KEY_ACTIVE | HISTORICAL_VALID | UNKNOWN_KEY | KEY_MISMATCH | KEY_REVOKED | KEY_EXPIRED
    reason: str
    record: Optional[TrustedKeyRecord] = None


class KeyRegistry:
    """Registro determinista de claves públicas confiables por (issuer, kid)."""

    SCHEMA = "gerarion-key-registry/1"

    def __init__(self, records: Optional[Iterable[TrustedKeyRecord]] = None) -> None:
        self._records: Dict[Tuple[str, str], TrustedKeyRecord] = {}
        if records:
            for rec in records:
                self.register(rec)

    def register(self, record: TrustedKeyRecord) -> TrustedKeyRecord:
        if not isinstance(record, TrustedKeyRecord):
            raise TypeError("register() exige una instancia de TrustedKeyRecord")
        self._records[(record.issuer, record.kid)] = record
        return record

    def register_signer(
        self,
        *,
        issuer: str,
        kid: str,
        signer,
        valid_from: Optional[Union[int, str]] = None,
        valid_until: Optional[Union[int, str]] = None,
        revoked_at: Optional[Union[int, str]] = None,
        revocation_reason: Optional[str] = None,
        scopes: Iterable[str] = (),
        historical: bool = False,
    ) -> TrustedKeyRecord:
        """Atajo para registrar directamente un HybridSigner autorizado."""
        rec = TrustedKeyRecord(
            issuer=issuer,
            kid=kid,
            pub_classical=signer.public_key_hex,
            pub_pqc=signer.public_key_pqc_hex,
            valid_from=valid_from,
            valid_until=valid_until,
            revoked_at=revoked_at,
            revocation_reason=revocation_reason,
            scopes=tuple(scopes),
            historical=historical,
        )
        return self.register(rec)

    def get(self, issuer: str, kid: str) -> Optional[TrustedKeyRecord]:
        return self._records.get((issuer, kid))

    def list_records(self) -> List[TrustedKeyRecord]:
        return [self._records[k] for k in sorted(self._records.keys())]

    def _is_historical_record(self, rec: TrustedKeyRecord) -> bool:
        """Determina si una clave válida en at_time es histórica (rotada o con
        ventana cerrada superada por otra clave del mismo issuer)."""
        if rec.historical or rec.revoked_at is not None:
            return True
        if rec.valid_until is not None:
            for (iss, other_kid), other in self._records.items():
                if iss == rec.issuer and other_kid != rec.kid:
                    if other.valid_until is None or (
                        other.valid_until > rec.valid_until
                    ) or (
                        other.valid_from is not None
                        and other.valid_from >= rec.valid_until
                    ):
                        return True
        return False

    def resolve(
        self,
        issuer: str,
        kid: str,
        at_time: Union[int, str],
        pub_classical: str,
        pub_pqc: str,
        *,
        required_scope: Optional[str] = None,
    ) -> KeyResolution:
        """Evalúa si (pub_classical, pub_pqc) están autorizadas para (issuer, kid)
        en el instante `at_time`."""
        rec = self._records.get((issuer, kid))
        if rec is None:
            return KeyResolution(
                trusted=False,
                key_status="UNKNOWN",
                code="UNKNOWN_KEY",
                reason=f"UNKNOWN_KEY: clave no registrada para issuer={issuer!r}, kid={kid!r}",
                record=None,
            )

        cand_c = (pub_classical or "").strip().lower()
        cand_p = (pub_pqc or "").strip().lower()
        # Comparación en tiempo constante de ambas ramas sin cortocircuito
        match_c = hmac.compare_digest(rec.pub_classical, cand_c)
        match_p = hmac.compare_digest(rec.pub_pqc, cand_p)
        if not (match_c and match_p):
            return KeyResolution(
                trusted=False,
                key_status="MISMATCH",
                code="KEY_MISMATCH",
                reason=(
                    f"KEY_MISMATCH: las claves públicas del sobre no coinciden "
                    f"con el registro para issuer={issuer!r}, kid={kid!r}"
                ),
                record=rec,
            )

        ins = _coerce_instant(at_time)
        if ins is None:
            raise ValueError("at_time es obligatorio para evaluar vigencia de clave")

        if rec.revoked_at is not None and ins >= rec.revoked_at:
            extra = f" ({rec.revocation_reason})" if rec.revocation_reason else ""
            return KeyResolution(
                trusted=False,
                key_status="REVOKED",
                code="KEY_REVOKED",
                reason=(
                    f"KEY_REVOKED: clave revocada en {rec.revoked_at} "
                    f"(evento en {ins}){extra}"
                ),
                record=rec,
            )

        if rec.valid_from is not None and ins < rec.valid_from:
            return KeyResolution(
                trusted=False,
                key_status="EXPIRED",
                code="KEY_EXPIRED",
                reason=(
                    f"KEY_EXPIRED: evento en {ins} anterior al inicio de vigencia "
                    f"valid_from={rec.valid_from}"
                ),
                record=rec,
            )

        if rec.valid_until is not None and ins > rec.valid_until:
            return KeyResolution(
                trusted=False,
                key_status="EXPIRED",
                code="KEY_EXPIRED",
                reason=(
                    f"KEY_EXPIRED: evento en {ins} posterior al fin de vigencia "
                    f"valid_until={rec.valid_until}"
                ),
                record=rec,
            )

        if required_scope and rec.scopes and required_scope not in rec.scopes:
            return KeyResolution(
                trusted=False,
                key_status="MISMATCH",
                code="KEY_MISMATCH",
                reason=(
                    f"KEY_MISMATCH: alcance {required_scope!r} no autorizado en "
                    f"scopes={rec.scopes}"
                ),
                record=rec,
            )

        if self._is_historical_record(rec):
            return KeyResolution(
                trusted=True,
                key_status="HISTORICAL",
                code="HISTORICAL_VALID",
                reason=(
                    f"HISTORICAL_VALID: firma válida dentro de la ventana histórica "
                    f"de la clave rotada ({issuer}, {kid})"
                ),
                record=rec,
            )

        return KeyResolution(
            trusted=True,
            key_status="ACTIVE",
            code="KEY_ACTIVE",
            reason=f"KEY_ACTIVE: clave activa verificada para ({issuer}, {kid})",
            record=rec,
        )

    def to_dict(self) -> dict:
        return {
            "schema": self.SCHEMA,
            "keys": [r.to_dict() for r in self.list_records()],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, data: dict) -> "KeyRegistry":
        if not isinstance(data, dict) or data.get("schema") != cls.SCHEMA:
            raise ValueError(f"schema de KeyRegistry inválido: {data.get('schema') if isinstance(data, dict) else None!r}")
        keys = data.get("keys")
        if not isinstance(keys, list):
            raise ValueError("campo 'keys' debe ser una lista")
        return cls(TrustedKeyRecord.from_dict(item) for item in keys)

    @classmethod
    def from_json(cls, raw_or_path: Union[str, Path]) -> "KeyRegistry":
        if isinstance(raw_or_path, Path):
            text = raw_or_path.read_text(encoding="utf-8")
        elif isinstance(raw_or_path, str) and not raw_or_path.lstrip().startswith("{") and Path(raw_or_path).is_file():
            text = Path(raw_or_path).read_text(encoding="utf-8")
        else:
            text = str(raw_or_path)
        return cls.from_dict(json.loads(text))
