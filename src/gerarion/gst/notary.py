# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Notario temporal encadenado por día Gerarion.

Mecanismo de obviación objetiva: nadie puede sostener una marca falsificada
frente a un notario que publica raíces encadenadas e inmodificables.

Arquitectura:

    day_root(n) = SHA-256("GUS2-DAY" || n || tree_root(n) || day_root(n-1))

Propiedades:

  - La cadena es un hash-chain sobre SHA-256: alterar un solo día exige
    recomputar todas las raíces posteriores y hacerlas coincidir con TODAS
    las réplicas publicadas del log (réplicas independientes, sin coordinación).
  - `seal_day` se invoca al cierre de cada día Gerarion: ancla el árbol de
    todas las marcas recibidas ese día.
  - El anclaje de días vacíos también se sella (raíz vacía definida): un
    notario no puede "inflar" silenciosamente los huecos.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Optional

EMPTY_ROOT = hashlib.sha256(b"GUS2-EMPTY").digest()


def _h(*parts: bytes) -> bytes:
    d = hashlib.sha256()
    for p in parts:
        d.update(len(p).to_bytes(4, "big") + p)
    return d.digest()


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        return EMPTY_ROOT
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicación de hoja impar (Bitcoin-style)
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _merkle_path(leaves: List[bytes], index: int) -> List[str]:
    path: List[str] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sib = idx ^ 1
        path.append(level[sib].hex())
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    return path


def verify_inclusion(leaf: bytes, path: List[str], index: int, root: bytes) -> bool:
    node = leaf
    for h, sib_hex in enumerate(path):
        sib = bytes.fromhex(sib_hex)
        if (index >> h) & 1:
            node = _node_hash(sib, node)
        else:
            node = _node_hash(node, sib)
    return node == root


class DayNotary:
    """Log de anclaje diario. Un objeto en memoria; export/import para réplicas."""

    def __init__(self) -> None:
        self._pending: List[bytes] = []
        self._days: Dict[int, dict] = {}
        self._chain: Dict[int, bytes] = {}
        self._prev_root: Optional[bytes] = None
        self._day: int = 0

    @property
    def previous_root(self) -> Optional[bytes]:
        return self._prev_root

    @property
    def current_day(self) -> int:
        """El día que está recibiendo marcas ahora (aún sin sellar)."""
        return self._day

    def append(self, payload: bytes) -> int:
        """Añade una marca (bytes canónicos) al día en curso; devuelve su índice de hoja."""
        index = len(self._pending)
        self._pending.append(_leaf_hash(payload))
        return index

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def inclusion_proof(self, day: int, leaf_index: int) -> dict:
        """Prueba de inclusión de una marca ya sellada."""
        rec = self._days.get(day)
        if rec is None:
            raise KeyError(f"Día {day} no sellado")
        leaves = [bytes.fromhex(x) for x in rec["leaves"]]
        return {
            "day": day,
            "index": leaf_index,
            "proof": _merkle_path(leaves, leaf_index),
            "root": rec["tree_root"],
            "day_root": rec["day_root"],
            "prev_root": rec["prev_root"],
        }

    def seal_day(self, day: int) -> dict:
        """Cierra el día: calcula tree_root y lo encadena con el día anterior.

        Los días deben sellarse en orden estricto (0, 1, 2, ...): el orden
        forma parte del anclaje.
        """
        if day in self._days:
            raise ValueError(f"Día {day} ya sellado")
        if self._day is not None and self._days and day != max(self._days) + 1:
            raise ValueError(f"Día {day} fuera de orden: se espera {max(self._days) + 1}")
        tree_root = _merkle_root(self._pending)
        prev = self._chain.get(day - 1, b"")
        day_root = _h(b"GUS2-DAY", day.to_bytes(8, "big"), tree_root, prev)
        record = {
            "day": day,
            "tree_root": tree_root.hex(),
            "prev_root": prev.hex(),
            "day_root": day_root.hex(),
            "leaves": [leaf.hex() for leaf in self._pending],
        }
        self._days[day] = record
        self._chain[day] = day_root
        self._prev_root = day_root
        self._pending = []
        self._day = day + 1
        return record

    def chain_head(self, day: int) -> bytes:
        """La raíz encadenada acumulada hasta el día dado (inclusive)."""
        if day not in self._chain:
            raise KeyError(f"Día {day} no sellado")
        head = self._chain[day]
        return head

    def verify_chain(self, days: List[int] | None = None) -> bool:
        """Recomputa la cadena completa desde el día 0 y compara."""
        head = b""
        for day in sorted(self._days):
            rec = self._days[day]
            leaves = [bytes.fromhex(x) for x in rec["leaves"]]
            if _merkle_root(leaves).hex() != rec["tree_root"]:
                return False
            if rec["prev_root"] != head.hex():
                return False
            head = _h(
                b"GUS2-DAY",
                day.to_bytes(8, "big"),
                bytes.fromhex(rec["tree_root"]),
                head,
            )
            if head.hex() != rec["day_root"]:
                return False
        return True

    def export(self) -> str:
        """Exporta el log completo INCLUYENDO las entradas pendientes sin
        sellar (S6): una réplica reiniciada desde este export no pierde
        marcas ni reutiliza índices de hoja."""
        return json.dumps(
            {
                "days": list(self._days.values()),
                "pending": [leaf.hex() for leaf in self._pending],
            },
            indent=2,
        )

    @classmethod
    def import_json(cls, raw: str) -> "DayNotary":
        notary = cls()
        data = json.loads(raw)
        for rec in data["days"]:
            day = rec["day"]
            notary._days[day] = dict(rec)
            notary._chain[day] = bytes.fromhex(rec["day_root"])
            notary._prev_root = bytes.fromhex(rec["day_root"])
        # restaura las pendientes y el cursor de día (los índices de hoja de
        # las pendientes siguen siendo válidos tras el reinicio)
        notary._pending = [bytes.fromhex(x) for x in data.get("pending", [])]
        notary._day = (max(notary._days) + 1) if notary._days else 0
        return notary
