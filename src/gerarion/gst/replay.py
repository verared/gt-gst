# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Almacenes anti-replay y anti-rollback para GST v2 (stdlib pura).

Proporciona:
- ``ReplayStore``: interfaz abstracta con operación atómica
  ``check_and_record(issuer, kid, seq, nonce, ins=None) -> ReplayDecision``.
- ``ReplayGuard``: implementación de referencia en memoria / archivo JSON
  atómico (adecuada para un solo proceso; falla en modo *fail-closed* ante
  corrupción).
- ``SQLiteReplayStore``: implementación transaccional concurrente sobre
  ``sqlite3`` (modo WAL, ``synchronous=FULL``, ``busy_timeout=5000``,
  transacciones ``BEGIN IMMEDIATE``), diseñada para despliegues multi-hilo
  y multi-worker sin condiciones de carrera TOCTOU.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional, Union

__all__ = [
    "ReplayDecision",
    "ReplayStore",
    "ReplayGuard",
    "SQLiteReplayStore",
]


@dataclass(frozen=True)
class ReplayDecision:
    """Resultado estructurado de evaluar (issuer, kid, seq, nonce)."""

    ok: bool
    status: str  # OK | REPLAY | SEQ_ROLLBACK
    reason: str = ""

    def __iter__(self) -> Iterator[Union[bool, str]]:
        """Compatibilidad con desempaquetado legado: ``ok, reason = store.check_and_record(...)``."""
        yield self.ok
        yield self.reason

    def __getitem__(self, idx: int) -> Union[bool, str]:
        return (self.ok, self.reason)[idx]

    def __len__(self) -> int:
        return 2

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ReplayDecision):
            return (self.ok, self.status, self.reason) == (
                other.ok,
                other.status,
                other.reason,
            )
        if isinstance(other, tuple) and len(other) == 2:
            return (self.ok, self.reason) == other
        return NotImplemented


class ReplayStore:
    """Contrato base para almacenes anti-replay y anti-rollback."""

    def check_and_record(
        self,
        issuer: str,
        kid: str,
        seq: int,
        nonce: str,
        ins: Optional[int] = None,
    ) -> ReplayDecision:
        raise NotImplementedError


def _normalize_replay_args(
    arg1,
    arg2,
    arg3,
    arg4,
    ins: Optional[int] = None,
) -> tuple:
    """Soporta tanto la firma nueva ``(issuer, kid, seq, nonce, ins=None)``
    como la firma legada de 4 argumentos ``(kid, nonce, seq, ins)``."""
    # Firma nueva: (issuer: str, kid: str, seq: int, nonce: str[, ins: int])
    if (
        isinstance(arg1, str)
        and isinstance(arg2, str)
        and isinstance(arg3, int)
        and not isinstance(arg3, bool)
        and isinstance(arg4, str)
    ):
        return arg1, arg2, arg3, arg4, ins
    # Firma legada: (kid: str, nonce: str, seq: int, ins: int)
    return "", arg1, arg3, arg2, arg4


class ReplayGuard(ReplayStore):
    """Guardia anti-replay y anti-rollback de referencia (un solo proceso).

    Persistencia opcional en archivo JSON con escritura atómica
    (temporal + ``os.replace`` + ``fsync``); sin ruta, opera solo en memoria.
    Para concurrencia multi-hilo o multi-worker en producción, usa
    :class:`SQLiteReplayStore`.

    FAIL-CLOSED: un archivo de estado corrupto, truncado o de estructura
    ajena envenena la guardia (``_poisoned = True``) y rechaza toda operación
    posterior en lugar de reiniciar ``seq`` en silencio.
    """

    def __init__(self, path: Optional[Union[str, Path]] = None) -> None:
        self.path = str(path) if path is not None else None
        self._seen: set = set()
        self._last_seq: dict = {}
        self._last_ins: dict = {}
        self._poisoned = False
        self._lock = threading.Lock()
        if self.path:
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
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
                        and len(x) in (2, 3)
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
                norm_seen = set()
                for item in seen:
                    if len(item) == 2:
                        norm_seen.add(("", item[0], item[1]))
                    else:
                        norm_seen.add((item[0], item[1], item[2]))
                self._seen = norm_seen
                self._last_seq = dict(last_seq)
                self._last_ins = dict(last_ins)
            except FileNotFoundError:
                pass
            except Exception:  # noqa: BLE001 - cualquier corrupción -> fail-closed
                self._seen, self._last_seq, self._last_ins = set(), {}, {}
                self._poisoned = True

    @staticmethod
    def _scope_key(issuer: str, kid: str) -> str:
        return f"{issuer}\x1f{kid}" if issuer else kid

    def check_and_record(
        self,
        arg1: str,
        arg2: str,
        arg3: int,
        arg4: Union[str, int],
        ins: Optional[int] = None,
    ) -> ReplayDecision:
        issuer, kid, seq, nonce, effective_ins = _normalize_replay_args(
            arg1, arg2, arg3, arg4, ins
        )
        with self._lock:
            if self._poisoned:
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason="estado persistido corrupto: guardia en fail-closed",
                )
            if (
                isinstance(seq, bool)
                or not isinstance(seq, int)
                or (
                    effective_ins is not None
                    and (isinstance(effective_ins, bool) or not isinstance(effective_ins, int))
                )
            ):
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason="seq/ins deben ser enteros",
                )
            if not isinstance(kid, str) or not kid or not isinstance(nonce, str) or not nonce:
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason="kid/nonce deben ser cadenas no vacías",
                )

            skey = self._scope_key(issuer, kid)
            nkey = (issuer, kid, nonce)
            if nkey in self._seen or ("", kid, nonce) in self._seen:
                return ReplayDecision(
                    ok=False,
                    status="REPLAY",
                    reason="replay: nonce ya registrado para esta clave",
                )
            last_seq = self._last_seq.get(skey, self._last_seq.get(kid))
            if last_seq is not None and seq <= last_seq:
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason=f"rollback: seq {seq} <= último confiable {last_seq}",
                )
            last_ins = self._last_ins.get(skey, self._last_ins.get(kid))
            if (
                effective_ins is not None
                and last_ins is not None
                and effective_ins < last_ins
            ):
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason=f"rollback: instante {effective_ins} < último confiable {last_ins}",
                )

            self._seen.add(nkey)
            self._last_seq[skey] = seq
            if effective_ins is not None:
                self._last_ins[skey] = effective_ins
            if self.path:
                self._save()
            return ReplayDecision(ok=True, status="OK", reason="")

    def _save(self) -> None:
        seen_out = [
            [k, n] if iss == "" else [iss, k, n]
            for (iss, k, n) in sorted(self._seen)
        ]
        data = {
            "seen": seen_out,
            "last_seq": self._last_seq,
            "last_ins": self._last_ins,
        }
        tmp = f"{self.path}.tmp.{os.getpid()}.{threading.get_ident()}"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.path)


class SQLiteReplayStore(ReplayStore):
    """Almacén anti-replay y anti-rollback transaccional y concurrente (SQLite WAL).

    Garantías:
    - ``PRAGMA journal_mode=WAL``, ``PRAGMA synchronous=FULL``,
      ``PRAGMA busy_timeout=5000``.
    - Transacciones ``BEGIN IMMEDIATE`` que verifican e insertan atómicamente
      la unicidad de ``(issuer, kid, nonce)`` y la monotonicidad estricta de
      ``seq`` (y ``ins`` cuando se suministra) por ``(issuer, kid)``,
      eliminando condiciones de carrera TOCTOU entre hilos o procesos.
    - Modo *fail-closed* ante archivos corruptos, truncados o esquemas
      manipulados.
    """

    SCHEMA_VERSION = "gerarion-sqlite-replay/1"

    def __init__(self, path: Union[str, Path] = ":memory:") -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._poisoned = False
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        try:
            if self.path != ":memory:" and os.path.exists(self.path):
                size = os.path.getsize(self.path)
                if 0 < size < 16:
                    # Archivo truncado/no-SQLite
                    self._poisoned = True
                    return
                if size >= 16:
                    with open(self.path, "rb") as fh:
                        header = fh.read(16)
                    if header != b"SQLite format 3\x00":
                        self._poisoned = True
                        return

            conn = sqlite3.connect(
                self.path,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            conn.execute("PRAGMA busy_timeout=5000;")
            if self.path != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=FULL;")

            qc = conn.execute("PRAGMA quick_check;").fetchone()
            if not qc or qc[0] != "ok":
                conn.close()
                self._poisoned = True
                return

            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table';"
                ).fetchall()
            }
            if tables:
                required = {"gst_meta", "gst_nonces", "gst_seq_state"}
                if not required.issubset(tables):
                    conn.close()
                    self._poisoned = True
                    return
                row = conn.execute(
                    "SELECT v FROM gst_meta WHERE k='schema';"
                ).fetchone()
                if not row or row[0] != self.SCHEMA_VERSION:
                    conn.close()
                    self._poisoned = True
                    return
            else:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS gst_meta ("
                    "k TEXT PRIMARY KEY, v TEXT NOT NULL);"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS gst_nonces ("
                    "issuer TEXT NOT NULL, "
                    "kid TEXT NOT NULL, "
                    "nonce TEXT NOT NULL, "
                    "seq INTEGER NOT NULL, "
                    "ins INTEGER, "
                    "PRIMARY KEY (issuer, kid, nonce));"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS gst_seq_state ("
                    "issuer TEXT NOT NULL, "
                    "kid TEXT NOT NULL, "
                    "last_seq INTEGER NOT NULL, "
                    "last_ins INTEGER, "
                    "PRIMARY KEY (issuer, kid));"
                )
                conn.execute(
                    "INSERT OR REPLACE INTO gst_meta (k, v) VALUES ('schema', ?);",
                    (self.SCHEMA_VERSION,),
                )
                conn.execute("COMMIT;")

            self._conn = conn
        except Exception:  # noqa: BLE001 - cualquier error de apertura -> fail-closed
            self._poisoned = True
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001
                    pass
                self._conn = None

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:  # noqa: BLE001
                    pass
                self._conn = None

    def check_and_record(
        self,
        arg1: str,
        arg2: str,
        arg3: int,
        arg4: Union[str, int],
        ins: Optional[int] = None,
    ) -> ReplayDecision:
        issuer, kid, seq, nonce, effective_ins = _normalize_replay_args(
            arg1, arg2, arg3, arg4, ins
        )
        with self._lock:
            if self._poisoned or self._conn is None:
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason="estado persistido corrupto: SQLiteReplayStore en fail-closed",
                )
            if (
                isinstance(seq, bool)
                or not isinstance(seq, int)
                or (
                    effective_ins is not None
                    and (isinstance(effective_ins, bool) or not isinstance(effective_ins, int))
                )
            ):
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason="seq/ins deben ser enteros",
                )
            if (
                not isinstance(issuer, str)
                or not isinstance(kid, str)
                or not kid
                or not isinstance(nonce, str)
                or not nonce
            ):
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason="issuer/kid/nonce inválidos",
                )

            conn = self._conn
            in_tx = False
            try:
                conn.execute("BEGIN IMMEDIATE;")
                in_tx = True

                dup = conn.execute(
                    "SELECT 1 FROM gst_nonces WHERE issuer = ? AND kid = ? AND nonce = ?;",
                    (issuer, kid, nonce),
                ).fetchone()
                if dup is not None:
                    conn.execute("ROLLBACK;")
                    return ReplayDecision(
                        ok=False,
                        status="REPLAY",
                        reason="replay: nonce ya registrado para esta clave",
                    )

                row = conn.execute(
                    "SELECT last_seq, last_ins FROM gst_seq_state WHERE issuer = ? AND kid = ?;",
                    (issuer, kid),
                ).fetchone()
                if row is not None:
                    last_seq, last_ins = row
                    if not isinstance(last_seq, int) or isinstance(last_seq, bool):
                        conn.execute("ROLLBACK;")
                        self._poisoned = True
                        return ReplayDecision(
                            ok=False,
                            status="SEQ_ROLLBACK",
                            reason="estado persistido corrupto: last_seq inválido (fail-closed)",
                        )
                    if seq <= last_seq:
                        conn.execute("ROLLBACK;")
                        return ReplayDecision(
                            ok=False,
                            status="SEQ_ROLLBACK",
                            reason=f"rollback: seq {seq} <= último confiable {last_seq}",
                        )
                    if (
                        effective_ins is not None
                        and last_ins is not None
                        and effective_ins < last_ins
                    ):
                        conn.execute("ROLLBACK;")
                        return ReplayDecision(
                            ok=False,
                            status="SEQ_ROLLBACK",
                            reason=f"rollback: instante {effective_ins} < último confiable {last_ins}",
                        )

                conn.execute(
                    "INSERT INTO gst_nonces (issuer, kid, nonce, seq, ins) VALUES (?, ?, ?, ?, ?);",
                    (issuer, kid, nonce, seq, effective_ins),
                )
                conn.execute(
                    "INSERT INTO gst_seq_state (issuer, kid, last_seq, last_ins) "
                    "VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(issuer, kid) DO UPDATE SET "
                    "last_seq = excluded.last_seq, "
                    "last_ins = COALESCE(excluded.last_ins, gst_seq_state.last_ins);",
                    (issuer, kid, seq, effective_ins),
                )
                conn.execute("COMMIT;")
                in_tx = False
                return ReplayDecision(ok=True, status="OK", reason="")
            except sqlite3.IntegrityError:
                if in_tx:
                    try:
                        conn.execute("ROLLBACK;")
                    except Exception:  # noqa: BLE001
                        pass
                return ReplayDecision(
                    ok=False,
                    status="REPLAY",
                    reason="replay: nonce ya registrado para esta clave",
                )
            except Exception as exc:  # noqa: BLE001 - corrupción o error de E/S -> fail-closed
                if in_tx:
                    try:
                        conn.execute("ROLLBACK;")
                    except Exception:  # noqa: BLE001
                        pass
                self._poisoned = True
                return ReplayDecision(
                    ok=False,
                    status="SEQ_ROLLBACK",
                    reason=f"estado persistido corrupto (fail-closed): {exc}",
                )
