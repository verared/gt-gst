# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Notario multi-réplica de producción (k-de-n sin coordinación).

Modelo de despliegue de producción del notario diario:

    - N réplicas independientes, cada una con su propio `DayNotary` y su
      propio estado; reciben las mismas marcas (fanout) en el mismo orden.
    - Cada réplica sella su día y **publica** su raíz diaria por su propio
      canal (GitHub, HTTP estático, IPFS, correo a auditores...). No hay
      comunicación entre réplicas al publicar: la coherencia es verificable
      después del hecho.
    - Un consumidor acepta un día si al menos `k` de `n` raíces diarias
      coinciden (quorum), cada raíz publicada deriva correctamente de su
      árbol (`tree_root`) y de su día previo, y el árbol del quorum contiene
      las marcas.
    - Cualquier réplica deshonesta (editada, comprometida o censurada) se
      manifiesta como: raíz divergente del quorum, cadena interna inválida,
      o ausencia de publicación (censura observable, no stealth).

Este módulo no sustituye la infraestructura de publicación: define el
protocolo, los formatos y las verificaciones que réplicas y consumidores
deben ejecutar.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .notary import DayNotary, verify_inclusion


@dataclass
class ReplicaPublication:
    """Raíces públicas de una réplica para un día cerrado."""

    replica: str
    day: int
    tree_root: str
    prev_root: str
    day_root: str

    def to_dict(self) -> dict:
        return {
            "replica": self.replica,
            "day": self.day,
            "tree_root": self.tree_root,
            "prev_root": self.prev_root,
            "day_root": self.day_root,
        }


def derive_day_root(day: int, tree_root: str, prev_root: str) -> str:
    """Derivación independiente (exportada para auditores externos)."""
    digest = hashlib.sha256()
    for part in (b"GUS2-DAY", day.to_bytes(8, "big"), bytes.fromhex(tree_root), bytes.fromhex(prev_root)):
        digest.update(len(part).to_bytes(4, "big") + part)
    return digest.hexdigest()


class NotaryReplica:
    """Una réplica honesta: notario propio + protocolo de publicación."""

    def __init__(self, name: str):
        self.name = name
        self.notary = DayNotary()

    def receive(self, payload: bytes) -> int:
        return self.notary.append(payload)

    def seal(self, day: int) -> ReplicaPublication:
        rec = self.notary.seal_day(day)
        return ReplicaPublication(
            replica=self.name,
            day=day,
            tree_root=rec["tree_root"],
            prev_root=rec["prev_root"],
            day_root=rec["day_root"],
        )

    def inclusion_proof(self, day: int, leaf_index: int) -> dict:
        return self.notary.inclusion_proof(day, leaf_index)

    def publish_history(self) -> List[dict]:
        """Todas las raíces publicadas de esta réplica, desde el día 0."""
        data = json.loads(self.notary.export())
        return [
            {
                "replica": self.name,
                "day": rec["day"],
                "tree_root": rec["tree_root"],
                "prev_root": rec["prev_root"],
                "day_root": rec["day_root"],
            }
            for rec in data["days"]
        ]

    def self_check(self) -> bool:
        return self.notary.verify_chain()


class NotaryCluster:
    """Grupo de réplicas independientes con verificación por quorum k-de-n."""

    def __init__(self, names: List[str], threshold: Optional[int] = None):
        if len(names) < 2:
            raise ValueError("se requieren al menos 2 réplicas")
        if threshold is None:
            threshold = len(names) // 2 + 1
        if threshold < 2:
            raise ValueError("quorum mínimo: 2")
        self.replicas = {name: NotaryReplica(name) for name in names}
        self.threshold = threshold

    # -- protocolo diario --------------------------------------------------
    def fanout(self, payload: bytes) -> Dict[str, int]:
        """Entrega la misma marca, en el mismo orden, a todas las réplicas."""
        return {name: rep.receive(payload) for name, rep in self.replicas.items()}

    def seal_day(self, day: int) -> Dict[str, ReplicaPublication]:
        """Cierra el día en todas las réplicas y devuelve sus publicaciones."""
        return {name: rep.seal(day) for name, rep in self.replicas.items()}

    # -- verificación de consumidor ---------------------------------------
    @staticmethod
    def quorum(
        publications: List[ReplicaPublication],
        threshold: int,
        known_replicas: Optional[Set[str]] = None,
    ) -> Tuple[bool, Optional[str], List[str]]:
        """Devuelve (quorum alcanzado, raíz dominante, réplicas divergentes).

        Cada IDENTIDAD (réplica por nombre) cuenta UNA sola vez por raíz:
        duplicar la lista de publicaciones de una misma réplica no infla el
        quórum (S5). La correspondencia nombre→clave pública se fija en el
        trust root del despliegue; con `known_replicas`, toda publicación
        de una identidad ajena se EXCLUYE del cómputo (y se reporta):
        una firma de un nodo no autorizado jamás alcanza quórum.
        """
        if not publications:
            return False, None, []
        if known_replicas is not None:
            publications = [p for p in publications if p.replica in known_replicas]
            if not publications:
                return False, None, []
        counts: Dict[str, set] = {}
        for pub in publications:
            counts.setdefault(pub.day_root, set()).add(pub.replica)
        best_root, best_names = max(counts.items(), key=lambda kv: len(kv[1]))
        divergent = sorted(
            {r for root, names in counts.items() if root != best_root for r in names}
        )
        return len(best_names) >= threshold, best_root, divergent

    def verify_day(
        self,
        publications: List[ReplicaPublication],
        threshold: Optional[int] = None,
        known_replicas: Optional[Set[str]] = None,
    ) -> dict:
        """Verificación completa de un día: quorum + derivación correcta de cada raíz.

        Solo computan para el quorum las publicaciones cuya `day_root` derivan
        correctamente de su `(tree_root, prev_root)`: una raíz que no deriva
        no puede sostener quorum aunque se replique. Con `known_replicas`,
        las identidades ajenas quedan fuera del quorum (anti-nodo-intruso).
        """
        threshold = threshold or self.threshold
        valid = [
            p for p in publications if derive_day_root(p.day, p.tree_root, p.prev_root) == p.day_root
        ]
        ok, root, divergent = self.quorum(valid, threshold, known_replicas)
        malformed = [p.replica for p in publications if p not in valid]
        unknown = (
            sorted({p.replica for p in publications
                    if known_replicas is not None and p.replica not in known_replicas})
            if known_replicas is not None
            else []
        )
        return {
            "ok": ok,
            "quorum_root": root,
            "divergent": sorted(set(divergent) | set(malformed)),
            "bad_derivation": malformed,
            "unknown_replicas": unknown,
        }

    # -- anclaje de marcas -------------------------------------------------
    def anchored(
        self,
        payload: bytes,
        day: int,
        leaf_index: int,
        publications: List[ReplicaPublication],
        proof: Optional[dict] = None,
    ) -> dict:
        """Verifica que una marca quedó incluida en el árbol del día del quorum.

        Secuencia: (1) quorum de raíces diarias; (2) el árbol (`tree_root`)
        de las réplicas en el quorum es único (las marcas fueron el mismo
        fanout); (3) la prueba de inclusión de la hoja contra ese árbol pasa.
        Si `proof` no se da, se toma de una réplica del quorum.
        """
        leaf = hashlib.sha256(b"\x00" + payload).digest()
        valid = [p for p in publications if derive_day_root(p.day, p.tree_root, p.prev_root) == p.day_root]
        ok, root_day, divergent = self.quorum(valid, self.threshold)
        if not ok:
            return {"ok": False, "errors": ["quorum no alcanzado"], "divergent": divergent}
        trees = {p.tree_root for p in publications if p.day_root == root_day}
        if len(trees) != 1:
            return {
                "ok": False,
                "errors": [f"árboles divergentes dentro del quorum: {len(trees)}"],
                "divergent": divergent,
            }
        tree_root = trees.pop()
        if proof is None:
            for name, rep in self.replicas.items():
                pub = next(p for p in publications if p.replica == name)
                if pub.day_root == root_day:
                    try:
                        proof = rep.inclusion_proof(day, leaf_index)
                        break
                    except KeyError:
                        return {"ok": False, "errors": [f"{name}: día {day} no sellado"], "divergent": []}
        included = verify_inclusion(leaf, proof["proof"], leaf_index, bytes.fromhex(tree_root))
        return {
            "ok": included,
            "errors": [] if included else ["la marca no está incluida en la raíz del quorum"],
            "divergent": divergent,
        }


def verify_bundle(
    bundle: List[dict],
    threshold: int,
    known_replicas: Optional[Set[str]] = None,
) -> dict:
    """Verificación standalone de un bundle publicado (consumidores externos).

    Con `known_replicas`, las identidades ajenas al trust root no computan
    para el quorum y se reportan en `unknown_replicas`.
    """
    pubs = [
        ReplicaPublication(
            replica=p["replica"],
            day=p["day"],
            tree_root=p["tree_root"],
            prev_root=p["prev_root"],
            day_root=p["day_root"],
        )
        for p in bundle
    ]
    valid = [p for p in pubs if derive_day_root(p.day, p.tree_root, p.prev_root) == p.day_root]
    ok, root, divergent = NotaryCluster.quorum(valid, threshold, known_replicas)
    malformed = [p.replica for p in pubs if p not in valid]
    unknown = (
        sorted({p["replica"] for p in bundle
                if known_replicas is not None and p["replica"] not in known_replicas})
        if known_replicas is not None
        else []
    )
    return {
        "ok": ok,
        "quorum_root": root,
        "divergent": sorted(set(divergent) | set(malformed)),
        "bad_derivation": malformed,
        "unknown_replicas": unknown,
    }
