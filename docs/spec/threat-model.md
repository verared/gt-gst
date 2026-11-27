# Modelo de amenazas — Gerarion Time `v3.4.0` (GUS v3.0.0)

Este documento define **qué protege el sistema, contra quién, y qué NO
protege**. Sin un modelo de amenazas explícito, cualquier afirmación de "no
falsificable" es mercadeo. Versión normativa en inglés:
[`../en/threat-model.md`](../en/threat-model.md) (EN > ES). Política de
divulgación: [`SECURITY.md`](../../SECURITY.md).

## 1. Activos

| Activo | Definición |
|---|---|
| Valor temporal (instante) | Conteo continuo `ins` + marca canónica `ts` |
| Orden histórico | La ordenación total de instantes y su secuencia de anclaje |
| Atribución | Atribución verificable de qué clave autorizada afirmó un instante |

## 2. Adversarios y capacidades asumidas

| Adversario | Capacidades |
|---|---|
| A-Local | Controla su propio reloj, logs y sistema; puede negar hechos |
| A-Suplantador | Genera sus propias claves híbridas válidas y reclama otro `issuer` / `kid` |
| A-Replay | Captura sobres válidos y los reenvía, de forma concurrente o diferida |
| A-Insider | Posee una clave de firma o notarial de una época pasada |
| A-Root | Tiene `root` en el host firmante (sin `TPM` / `HSM`) |
| A-Persistente | Compromete un notario completo (claves, estado, disco) |
| A-Jurisdiccional | Vigila, censura y fuerza legalmente a un notario de su dominio |
| A-Cuántico | Ordenador cuántico con millones de qubits lógicos (horizonte 2035+) |
| A-Social | Campaña de desinformación sobre qué hora "fue" |

## 3. Perfil normativo y niveles de verificación

`GST v2` firma `b"GUS3-GST-V2\x00" + JCS(payload)` (RFC 8785, enteros dentro
de `±(2^53 - 1)`) con **Ed25519 + ML-DSA**; el descriptor de algoritmos y
claves va dentro del payload firmado. La verificación
(`gerarion.gst.v2.verify`) devuelve un `VerificationResult` con tres niveles
independientes:

1. **`crypto`** — validez matemática, JCS, `event_hash`, anti-downgrade y
   firmas duales.
2. **`identity`** — autorización de `(issuer, kid)` mediante `KeyRegistry` y
   anti-replay transaccional (`ReplayStore`).
3. **`temporal`** — procedencia/calidad del reloj de `gt-gts`; `UNKNOWN`
   cuando no se aporta una lectura autenticada.

`sealed` cubre los niveles 1 y 2. `overall_trusted` exige además evidencia
temporal vinculada y aceptada por el host y una lectura `VERIFIED`.

## 4. Garantías y sus premisas

### G1 — Toda alteración de un sobre firmado es detectable

Altera un bit del payload firmado y la verificación falla (detección
determinista de manipulación, no imposibilidad física). **Premisa:** SHA-256
resiste colisión y preimagen; Ed25519 y ML-DSA no están rotos.

### G2 — Una firma válida de una clave no autorizada se rechaza

Un sobre autofirmado que reclama otro `issuer` / `kid` pasa el nivel 1 pero
falla el nivel 2 (`KEY_MISMATCH` / `UNKNOWN_KEY`). Las claves se comparan en
tiempo constante (`hmac.compare_digest`) contra el `KeyRegistry`, que además
impone ventanas de vigencia (`KEY_EXPIRED`), revocación (`KEY_REVOKED`) y
mantiene auditables las claves rotadas (`HISTORICAL_VALID`). Una clave
rechazada nunca modifica el estado de replay del emisor legítimo.
**Premisa:** el integrador distribuye el `KeyRegistry` por un canal confiable.

### G3 — Replay y rollback se rechazan de forma atómica

`SQLiteReplayStore` (`PRAGMA journal_mode=WAL`, `synchronous=FULL`,
`busy_timeout=5000`, `BEGIN IMMEDIATE`) comprueba y registra en una sola
transacción la unicidad de `(issuer, kid, nonce)` y la monotonicidad estricta
de `seq`, eliminando la ventana TOCTOU con carga multi-hilo / multi-worker
(probado con 16 hilos concurrentes: exactamente uno aceptado). Un estado
corrupto o ajeno pone el almacén en modo *fail-closed* en lugar de reiniciar
`seq`. **Premisa:** la base de datos no se revierte desde un backup antiguo;
si debe restaurarse, se rota a un `kid` nuevo.

### G4 — El pasado del notario es inmutable sin detección

El `day_root` del día n incluye el `day_root` de n-1. Alterar un día exige
recomputar toda la cadena posterior **y** publicarla coherente en cada réplica
que un verificador consulte. **Premisa:** al menos una réplica independiente
permanece honesta y accesible.

### G5 — El retroceso de reloj se detecta

`gt-gts` evalúa las lecturas con la tupla completa `(instant, nanos)` contra un
ancla persistida: un retroceso sub-segundo es `REJECTED`, y `VERIFIED` exige
una fuente autenticada explícitamente (`require_authenticated`). **Premisa:**
el atacante no revierte el almacén de anclas.

### G6 — Compatibilidad cuántica y agilidad

La capa de firma combina un algoritmo clásico y uno post-cuántico (retículos);
la capa de hash solo enfrenta la aceleración cuadrática de Grover (margen
2^128). `alg` es un campo de primera clase: una ruptura futura se resuelve
firmando con un algoritmo nuevo y re-anclando la evidencia antigua, nunca
reescribiendo el pasado. **Premisa:** el esquema híbrido es todo-o-nada; una
firma solo clásica o solo post-cuántica se rechaza.

## 5. Ataques concretos y mitigaciones

| Ataque | Resultado |
|---|---|
| Falsificar un sobre individual | Exige romper Ed25519 **y** ML-DSA (G1) |
| Sobre autofirmado que suplanta a un emisor | Nivel 2 `KEY_MISMATCH` / `UNKNOWN_KEY`; `overall_trusted = False` (G2) |
| Downgrade quitando una rama de firma | El descriptor va en los bytes firmados; sobre inválido (G1) |
| Replay de un sobre válido (secuencial o concurrente) | `REPLAY` / `SEQ_ROLLBACK` del `ReplayStore` atómico (G3) |
| Verificación sin almacén de replay | Nivel 2 inválido salvo `allow_unchecked_replay=True`; reportado como `SKIPPED` |
| Uso de una clave expirada o revocada | `KEY_EXPIRED` / `KEY_REVOKED`; los eventos previos siguen `HISTORICAL` |
| Base de replay corrupta / truncada | *Fail-closed*: todo rechazado, `seq` jamás se reinicia en silencio |
| Reloj local atrasado | Ancla anti-rollback sub-segundo → `REJECTED` (G5) |
| Retro-editar el log del notario | Exige romper G4 (todas las réplicas) |
| Compromiso de clave notarial | Los `day_root` publicados no se retractan; daño limitado a firmas futuras; rotación firmada |
| Ataque cuántico a la firma | Deberían caer ambas ramas (G6) |
| Bug de conversión | Vectores normativos en CI; spec y código no divergen en silencio |
| Atacante con `root` en el host firmante | **No mitigado** sin `TPM` / `HSM` (ver §6) |

## 6. Lo que este sistema NO garantiza (límites, en honestidad)

1. **Aún no hay auditoría criptográfica independiente.** `gt-gst` y el notario
   no han sido revisados por un tercero independiente.
2. **Aún no hay custodia de claves en hardware (`TPM` / `HSM`).** Un atacante
   con `root` en el host firmante puede usar las claves privadas para firmar
   eventos arbitrarios con el `(issuer, kid)` autorizado; el robo de claves
   solo se detecta a posteriori mediante revocación. No uses `gt-gst` en
   decisiones críticas de producción hasta cerrar este punto y el anterior.
3. **Un sello no certifica la hora física.** Un firmante con clave autorizada
   aún puede firmar una hora falsa. Comprueba la incertidumbre y el alcance
   del ancla independiente antes de usar un sobre anclado como evidencia temporal.
4. **No garantiza la exactitud del reloj de pared de un dispositivo.** NTP, PTP
   y GNSS son capas externas; `gt-gts` clasifica lecturas, no disciplina el
   reloj.
5. **No sobrevive a un conspirador que controle todas las réplicas desde el
   origen.** Es el límite constitutivo de *cualquier* notarización.
6. **No define qué hora civil mostrar a humanos.** Presentación, zona horaria e
   idioma son capas de aplicación.
7. **No sustituye los controles del SO, del hardware ni de la red.**
   `gt-tslr`, `gt-gcerts`, el perfil Roughtime y el perfil RFC 3161 son
   EXPERIMENTALES y están separados del núcleo.
8. **El código legado queda fuera de alcance.** `WOTS+`
   (`src/gerarion/deprecated/hashots.py`) y la API `GST v1` son artefactos
   educativos deprecados.

## 7. Presupuesto de coste de falsificación (resumen)

| Objetivo del atacante | Costo mínimo |
|---|---|
| Alterar 1 bit de un sobre firmado | Romper Ed25519 y ML-DSA, o hallar una preimagen SHA-256 (2^256; 2^128 con Grover) |
| Suplantar a un emisor | Obtener las claves privadas registradas (ver §6.2) |
| Reescribir 1 día con R réplicas honestas | Reescribir R logs de forma coherente y neutralizar la memoria externa de R comunidades |
| Falsificar el pasado no anclado | Solo genera "afirmaciones"; ningún notario las acredita como hechos |

La tesis: **el coste de mentir sobre el tiempo debe superar el valor de
cualquier mentira temporal.** La replicación, las cadenas de raíces y la
autorización de claves son el mecanismo — no la fe, no el decreto.
