# Sellado criptográfico de eventos

Parte de la suite de referencia **Gerarion** (verared/gerarion `v3.2.0`,
Gerarion Universal Standard). Este directorio es un **paquete de
exportación** listo para publicarse (o consumirse) como repositorio
satélite `verared/gt-gst`; conserva las rutas relativas del repositorio
base para componer módulos.

## El problema único que resuelve

El sobre firmado GST v2: canonicalización RFC 8785 (JCS), firma híbrida Ed25519 + ML-DSA con protección anti-downgrade, ReplayGuard persistente y notario Merkle diario con quórum.

## Estado normativo

- **Estable (GST v2)** — línea base `v3.2.0` (aritmética y vectores
  congelados: GUS v3.0.0).
- Especificación(es) incluida(s): `docs/specs/GST.es.md`, `docs/specs/GST.en.md`, `docs/spec/threat-model.md`, `docs/en/threat-model.md`

## Dependencias

- `gt-core` (*verared/gt-core*): tipos base y servicios del núcleo.
Base común: `verared/gerarion` `v3.2.0`.

## Contenido

- `LICENSE`
- `NOTICE`
- `docs/en/threat-model.md`
- `docs/spec/threat-model.md`
- `docs/specs/GST.en.md`
- `docs/specs/GST.es.md`
- `src/gerarion/gst/` (6 archivos)

## Uso offline

No requiere red, cuentas, registro de paquetes ni frameworks:

```bash
python3 -c 'import sys; sys.path.insert(0, "src"); import gerarion'
```

## Verificación

Con Python ≥ 3.9 y `reuse` instalado:

```bash
reuse lint                                    # licencias al 100 %
# (las pruebas viven en la suite de verared/gerarion)
```

## Contrato de sincronización con `verared/gerarion`

Este paquete es **generado, no editado a mano**: se regenera byte a
byte desde `verared/gerarion v3.2.0` con
`python3 tools/export_module.py --module gt-gst --out <dir>`. La fuente
de verdad normativa (especificaciones, vectores CC0, núcleos de
referencia de las tres plataformas y la batería completa) permanece en
`verared/gerarion`; los satélites `verared/gt-gst` la consumen y no forkean la
aritmética. Las actualizaciones fluyen regenerando la exportación desde
un tag del repositorio base; nunca editando los archivos exportados.
