# Especificación GST — Sellado criptográfico de eventos

- **Estado:** Estable (`GST v2`, requiere auditoría criptográfica externa independiente y custodia TPM/HSM antes de decisiones críticas de producción); perfiles TSA/notario **Experimentales en despliegue** ·
  **Versión:** 1.1.0 · **Línea base:** GUS v3.0.0 / suite `v3.3.0`
- **Edición consolidada:** [`../spec/gus-3.0.0.md`](../spec/gus-3.0.0.md) (§7–§8) ·
  Perfil: [`../profiles/gus-3161-perfil.md`](../profiles/gus-3161-perfil.md)
- **Licencia:** CC-BY-4.0 · Mantenida por: verared contributors

## 1. Alcance

El sobre firmado **GST v2** (*Gerarion Signed Timestamp*): canonicalización
JSON determinista (RFC 8785), vinculación del evento, firma híbrida
simultánea Ed25519 + ML-DSA con protección anti-*downgrade*, protección
anti-replay/anti-rollback y los anclajes externos (notario Merkle y RFC 3161).
No cubre la calidad previa del reloj (dominio GTS) ni el formato de la marca
(dominio GUS).

### Perfil criptográfico normativo

| Aspecto | Declaración normativa |
|---|---|
| **Algoritmo normativo (`GST v2`)** | Firma híbrida **Ed25519 + ML-DSA** sobre payload canonicalizado con **RFC 8785 (JCS)** (enteros estrictamente dentro de IEEE-754 `binary64` `±(2^53 - 1)`), separación de dominio `GUS3-GST-V2`, descriptor de algoritmos y claves incluido dentro de los bytes firmados (protección **anti-downgrade**), contador monotónico `seq` + `nonce` con `ReplayGuard` *fail-closed* y notario Merkle diario opcional. |
| **Algoritmo deprecado / educativo** | `WOTS+` / `WotsMerkleSigner`, aislado en `src/gerarion/deprecated/hashots.py` con `DeprecationWarning` explícito; **fuera** del perfil normativo `GST v2` y no apto para producción. |
| **Cobertura de pruebas y límite de auditoría** | **Cubierto por pruebas:** núcleo aritmético, RFC 8785 JCS (entradas hostiles y rechazo `> 2^53 - 1`), verificación dual híbrida, rechazo anti-downgrade, `ReplayGuard` *fail-closed*, anclas sub-segundo e integración de satélites ensamblados. **Pendiente:** auditoría criptográfica externa independiente de terceros y custodia de claves en hardware (TPM/HSM) antes de decisiones críticas de producción. |

## 2. Reglas normativas

1. **Canonicalización RFC 8785 (JCS):** toda firma y verificación opera
   sobre los bytes UTF-8 exactos de `jcs.dumps(payload)` (claves ordenadas
   por unidades de código UTF-16, escape mínimo, números IEEE 754 en texto
   ECMAScript, `NaN`/`Infinity` rechazados, enteros fuera de ±(2⁵³−1)
   rechazados — deben viajar como cadenas decimales).
2. **Separación de dominio:** los bytes firmados son
   `b"GUS3-GST-V2\x00" + canonical_bytes`.
3. **Campos obligatorios del sobre v2:** `gst_version: "2.0"`, `ts`
   (marca GUS canónica), `ins` (int64 segundos), `nanos` (0..999.999.999),
   `scale: "TCJ"` (o `"TAI"` explícito), `event_hash` (obligatorio,
   `sha256:<hex>` o `sha512:<hex>`), `kid` e `issuer`, `nonce`
   (aleatorio criptográfico) y `seq` (contador monotónico),
   `policy_version`. Un sobre `v2` sin `event_hash` válido se rechaza.
4. **Firma híbrida:** los descriptores completos de algoritmo
   (`alg`, `kid_classical`, `kid_pqc`) viven **dentro del payload
   canonicalizado antes de firmar**; eliminar o degradar la firma
   post-cuántica invalida también la clásica. La verificación en modo
   híbrido exige que **ambas** firmas sean válidas; falta o fallo de
   cualquiera → `REJECTED`.
5. **Anti-replay persistente:** `ReplayGuard` registra `(kid, nonce)`
   vistos y el último `(seq, ins)` fiable; rechaza repeticiones exactas y
   retrocesos de contador o reloj. Estado persistido corrupto → *fail-closed*
   (no se reinicia `seq` en silencio).
6. **Trazabilidad del contenido:** `event_hash` ancla el dato externo;
   el sello certifica la existencia y el orden del evento, no su veracidad.
7. **Notario Merkle diario:** `day_root(n) = SHA-256("GUS2-DAY" || n ||
   tree_root(n) || day_root(n-1))`; días sellados en orden estricto, sin
   huecos; raíces publicadas en réplicas independientes. El quórum exige
   firmantes distintos: respuestas duplicadas del mismo nodo no cuentan.
8. **Perfil RFC 3161 (GUS-3161):** la TSA certifica la existencia de los
   bytes canónicos de la GST en su `genTime`; el notario certifica el
   orden. Sellos complementarios; verificación offline contra el trust
   root declarado.
9. **Aviso de madurez del adaptador de referencia:** la familia hash-only
   (WOTS16-Merkle, `hashots.py`) es EDUCATIVA y no está auditada;
   producción exige FIPS 203/204/205 con implementaciones auditadas.

## 3. Fuentes de verdad

| Componente | Implementación |
|---|---|
| Sobre y verificación | `src/gerarion/gst/envelope.py` |
| JCS | `src/gerarion/gst/jcs.py` |
| Firmantes híbridos | `src/gerarion/gst/adapters.py` |
| Notario y quórum | `src/gerarion/gst/notary.py`, `notary_cluster.py` |
| CLI de verificación | `tools/verify_gus.py` |

## 4. Vectores aplicables

- Vectores de prueba dedicados en `tests/test_jcs_gstv2.py`,
  `tests/test_adversarial_security.py`, `tests/test_notary_cluster.py`
  (positivos, replay, rollback, *downgrade*, JCS hostil).
- El notario firma el día actual: los vectores cubren estructura, no
  sellos fechados.

## 5. Madurez y límites

- Formato GST v2 + JCS + híbrido: **estables** (endurecidos en
  v3.0.1/v3.1.1).
- TSLR y GCERTS son perfiles experimentales separados (ver sus fichas).
- La firma no hace inviolable el valor: fija el contenido a una clave y
  habilita detección determinista de manipulación y trazabilidad
  criptográfica post-cuántica; la objetividad histórica exige réplicas
  de notario independientes y confianza previamente fijada.

## 6. Referencias

- `docs/spec/threat-model.md`, `docs/notary-runbook.md`,
  `docs/audit/AUDIT-REPORT-v3.0.0.md` (hallazgos A-*, B-*).
