# Modelo de amenazas — GUS 2.0

Este documento define **qué protege el sistema, contra quién, y qué NO
protege**. Es la base de cualquier evaluación de seguridad seria: sin
modelo de amenazas explícito, cualquier afirmación de "no falsificable" es
mercadeo.

## 1. Activos

| Activo | Definición |
|---|---|
| Valor temporal (instante) | Conteo continuo `ins` + marca canónica `ts` |
| Orden histórico | La dominación total de instantes y su secuencia de anclaje |
| No-repudio | Atribución verificable de quién afirmó un instante y cuándo |

## 2. Adversarios y capacidades asumidas

| Adversario | Capacidades |
|---|---|
| A-Local | Controla su propio reloj, logs y sistema; puede negar hechos |
| A-Insider | Posee una clave notarial o de firma de una época pasada |
| A-Persistente | Compromete un notario completo (claves, estado, disco) |
| A-Jurisdiccional | Vigila, censura y fuerza legalmente a un notario de su dominio |
| A-Cuántico | Ordenador cuántico con millones de qubits lógicos (horizonte 2035+) |
| A-Social | Campaña de desinformación sobre qué hora "fue" |

## 3. Garantías y sus premisas

### G1 — Toda alteración de una GST firmada es detectable

Altera un bit de `ts`, `ins`, `sig` o `pub` y la verificación falla: la
garantía es de DETECCIÓN DETERMINISTA de manipulación, no de
"imposibilidad física" (esa formulación absoluta no es una garantía
verificable).
**Premisa:** SHA-256 es resistente a colisión y preimagen. El coste de
falsificar: 2^256 de trabajo serial (o 2^128 en el caso Grover cuántico).
Ambos superan por órdenes de magnitud cualquier valor temporal defendible.

### G2 — El pasado del notario es inmutable sin detección

El `day_root` del día n incluye el `day_root` de n-1. Alterar cualquier día
exige recomputar toda la cadena posterior **y** publicarla coherente en cada
réplica que un verificador consulte.
**Premisa:** al menos una réplica independiente permanece honesta y
accesible. Este es el único requisito social de todo el sistema, y se satisface
con réplicas organizativa y jurisdiccionalmente separadas.

### G3 — Compatibilidad cuántica

Las firmas de referencia y los algoritmos recomendados (SLH-DSA, ML-DSA, LMS,
XMSS) son hash-only o de rejilla; frente a ellos, el atacante cuántico solo
obtiene la aceleración cuadrática de Grover sobre el hash.
**Premisa:** 2^128 de margen post-Grover se considera adecuado a horizonte de
100+ años. La especificación permite, además, migrar a SHA-384 o SHAKE256
mediante el campo `alg` si el margen se estima insuficiente.

### G4 — Agilidad criptográfica

`alg` es un campo de primera clase. Una ruptura futura (de SHA-256 o del
esquema de firma) no invalida el formato: se firma con un algoritmo nuevo y
las marcas antiguas se re-anclan (re-timestamping: las raíces antiguas se
incluyen como hojas del notario moderno). El tiempo no se re-escribe: se
re-protege, y esa operación es pública en el log.

### G5 — Un firmante local no puede hacer valer su propio reloj

Un emisor malicioso puede firmar *cualquier marca* con su propia clave: eso
es una afirmación, no una hora. La verificabilidad objetiva solo existe
respecto al log del notario: una marca sin anclaje es una *afirmación*
(estado "unsigned"); con anclaje, es un *hecho notariado*. Los consumidores
deciden el grado de confianza según el anclaje.
**Premisa aceptada explícitamente:** ninguna criptografía impide que un
sistema mienta sobre su reloj interno; el notario impide sostener esa mentira
frente a terceros.

### G6 — Plan de migración post-cuántica (por fases, sin fechas prometidas)

Estado real en 2.5.0b1 y ruta candidata a RC/1.0:

- **Hoy:** Ed25519 solo en el perfil de anclaje de red (Roughtime); SLH-DSA
  (FIPS 205) adaptador opcional (`gerarion[slh]`); ML-DSA (FIPS 204)
  adaptador opcional (`gerarion[pqc]`, `cryptography>=47`). La firma
  hash-only de referencia sigue deprecada y bloqueada por defecto.
- **Fase 1 (IMPLEMENTADA en 3.0.0, esquema GST v2):** firma híbrida
  simultánea (Ed25519 + ML-DSA) sobre los mismos bytes canónicos JCS
  (RFC 8785), con el descriptor de algoritmos dentro del payload firmado:
  quitar o degradar la rama post-cuántica invalida también la clásica
  (anti-downgrade estructural). La verificación híbrida es todo-o-nada.
- **Fase 2 (objetivo):** los verificadores de alto nivel exigen el
  componente post-cuántico; una firma solo-clásica se reporta como degradada.
- **Fase 3 (objetivo):** nuevo anclaje exclusivamente post-cuántico;
  Ed25519 queda solo para leer evidencia histórica (re-firma con preservación
  de cadena, sin reescritura del pasado — ver G4).

**Premisa:** la migración es un cambio de capa de firma (versión menor;
G4), no del kernel; los vectores normativos del calendario no cambian.

## 4. Ataques concretos y mitigaciones

| Ataque | Resultado |
|---|---|
| Falsificar una GST individual | Requiere romper G1 |
| Retro-editar el log del notario | Requiere romper G2 (todas las réplicas) |
| Rollback del notario a un estado pasado | Detectable por divergencia con réplicas publicadas; el sellado en orden estricto no deja ventana oculta |
| Reuso de hoja OTS | Estado auditado; el anclaje diario registra el índice usado; hoja repetida = alarma pública |
| Compromiso de clave notarial | Los `day_root` ya publicados no se pueden retractar; el daño queda limitado a firmas futuras; rotación firmada (spec §7.1) |
| Ataque cuántico a la firma | G3: hash-only no degrada más allá de Grover |
| Bloqueo o censura de un notario | El sistema requiere N notarios; las marcas sobreviven a la pérdida individual |
| Long-range (insider firma "30 años atrás") | No acreditable como hecho: la inclusión exige el `day_root` de ese día, ya existente y publicado. Solo puede producir *afirmaciones* detectables |
| Bug de conversión | Suite de vectores normativos en CI; la spec y el código no pueden divergir silenciosamente |

## 5. Lo que este sistema NO garantiza (límites, en honestidad)

1. **No garantiza la exactitud del reloj de pared de un dispositivo.** La
   sincronización civil (NTP, GNSS) es una capa externa. GUS garantiza
   *orden* y *notarización*, no el ajuste fino del reloj local.
2. **No sobrevive a un conspirador que controle todas las réplicas desde el
   origen.** Es el límite constitutivo de *cualquier* notarización. Mitigación
   estructural: las claves públicas publicadas con antelación no se pueden
   cambiar retroactivamente sin dejar discontinuidad observable.
3. **No define qué hora civil mostrar a humanos.** Presentación, zona horaria
   e idioma son capas de aplicación.
4. **GUS no sustituye los controles del sistema ni de la red.** Los
   controles de seguridad del sistema operativo, el aislamiento de hardware
   y las mitigaciones de red quedan FUERA del alcance de GUS: este sistema
   los complementa, nunca los reemplaza. TSLR y GCERTS son perfiles
   EXPERIMENTALES separados del núcleo.
5. **La implementación de referencia NO es código de producción.** Es
   ejecutable, exacta y verificada para *vectores*; el despliegue exige
   bibliotecas auditadas (FIPS 204, FIPS 205, RFC 8554). El adaptador
   `slh-dsa` de la referencia es biblioteca de **código abierto sin
   auditoría ni validación FIPS verificadas** (útil para
   interoperabilidad y vectores, no un módulo certificado).

## 6. Presupuesto de coste de falsificación (resumen)

| Objetivo del atacante | Costo mínimo |
|---|---|
| Alterar 1 bit de una GST | 2^256 (preimagen SHA-256) |
| Romper una firma (atacante cuántico) | 2^128 (Grover) |
| Reescribir 1 día con R réplicas honestas | Reescribir R logs de forma coherente y neutralizar la memoria externa de R comunidades |
| Falsificar el pasado no anclado | Solo genera "afirmaciones" sin anclaje; ningún notario las acredita como hechos |

La tesis de GUS: **el coste de mentir sobre el tiempo debe superar el valor
de cualquier mentira temporal.** La replicación y las cadenas de raíces son
el mecanismo que lo sostiene — no la fe, no el decreto.
