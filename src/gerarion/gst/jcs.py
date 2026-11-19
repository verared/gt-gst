# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 verared contributors
"""Canonicalización JSON RFC 8785 (JCS) — stdlib puro, sin dependencias.

Implementa el Serializador de Canonicalización JSON (JSON Canonicalization
Scheme, RFC 8785) para los sobres GST v2:

- UTF-8 sin BOM; escape mínimo (solo `"`, ``\\`` y los controles < 0x20,
  con las formas cortas ``\\b \\t \\n \\f \\r`` y ``\\u00XX`` para el resto);
  el resto de caracteres Unicode viaja literal (UTF-8).
- Claves de objeto ordenadas por sus unidades de código UTF-16 (orden
  lexicográfico de ``UTF-16BE``, que coincide con el orden del estándar
  ECMAScript para cadenas bien formadas sin sustitutos huérfanos).
- Números en la representación determinista de IEEE 754 doble precisión
  con la sintaxis de ECMAScript (algoritmo de la Appendix B del RFC 8785):
  - enters sin parte decimal ni exponente;
  - `±0` → `0`; NaN/Inf → error (JCS no los representa);
  - punto fijo para 1e-6 <= |x| < 1e21, notación `e` fuera de ese rango,
    con el dígito significativo más corto que vuelve a redondear al mismo
    double (dígitos obtenidos de `repr`, que en CPython usa el algoritmo
    de dígitos más corto de Ryu/Grisu equivalente al de ECMAScript).
  - ENTEROS FUERA DE BINARY64 (adenda v3.1.1): RFC 8785 exige que todo
    número se serialice como un `Number` de ECMAScript (IEEE 754 binary64
    con el algoritmo de la Appendix B). Un entero Python de precisión
    arbitraria que supere ±(2^53 − 1) NO es interoperable: dos
    implementaciones conformantes deben poder reproducir los mismos
    bytes, y a partir de 2^53 el valor pierde dígitos bajos al convertirse
    a double. Por consiguiente `dumps()` rechaza tales enteros con
    `JcsError`; el productor que necesite representar un valor de 64 bits
    mayor (p. ej. un `ins` de horizonte lejano o un contador de 63 bits)
    DEBE codificarlo previamente como cadena decimal
    (``str(value)``), que JCS canonicaliza como texto sin ambigüedad.
- `true`/`false`/`null` literales; los objetos anidados y los arrays se
  procesan en profundidad. Los bool No son números (chequeo explícito:
  `bool` es subclase de `int` en Python).

Superficie: `dumps(obj) -> str`, `dumps_bytes(obj) -> bytes` (UTF-8),
`canonical_bytes(obj) -> bytes` (alias semántico para firmas).
"""

from __future__ import annotations

import math
from typing import Any

__all__ = ["dumps", "dumps_bytes", "canonical_bytes", "JcsError",
           "BINARY64_MAX_INT", "BINARY64_MIN_INT"]

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


class JcsError(ValueError):
    """Valor no canonizable (NaN/Inf, sustituto huérfano, tipo ajeno a JSON,
    entero fuera del rango interoperable de IEEE 754 binary64)."""


# RFC 8785 §3.2.2.3: un Number de ECMAScript es IEEE 754 binary64; los
# enteros con |v| > 2^53 − 1 no tienen representación exacta e
# interoperable y nunca deben serializarse como number (adenda v3.1.1).
BINARY64_MAX_INT = 2**53 - 1   # 9007199254740991
BINARY64_MIN_INT = -(2**53 - 1)  # -9007199254740991


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= code < 0x7F:
            out.append(ch)
        elif code in _ESCAPES:
            out.append(_ESCAPES[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            # Los sustitutos huérfanos no son Unicode válido (JCS exige
            # cadenas Unicode bien formadas): se rechazan, nunca se "arreglan".
            if 0xD800 <= code <= 0xDFFF:
                raise JcsError(f"cadena con sustituto huérfano U+{code:04X}")
            out.append(ch)
    out.append('"')
    return "".join(out)


def _es6_number(x: float) -> str:
    """Formato numérico determinista de ECMAScript para un double finito.

    Reconstruye el algoritmo Number::toString (RFC 8785, Appendix B) a partir
    de los dígitos decimales más cortos que representan el mismo double
    (`repr` de CPython implementa ese algoritmo para IEEE 754 binary64).
    """
    if x != x or x in (float("inf"), float("-inf")):
        raise JcsError("NaN/Infinity no es representable en JCS")
    if x == 0:
        return "0"  # ±0 → "0" (RFC 8785 §3.2.2.3)
    sign = "-" if x < 0 else ""
    rep = repr(abs(x))
    if "e" in rep or "E" in rep:
        mant_str, exp_s = rep.replace("E", "e").split("e")
        exp = int(exp_s)
    else:
        mant_str, exp = rep, 0
    int_part, _, frac = mant_str.partition(".")
    digits_raw = int_part + frac
    dot_pos = len(int_part)
    stripped = digits_raw.lstrip("0")
    first_sig = len(digits_raw) - len(stripped)  # índice del 1er dígito significativo
    s = stripped.rstrip("0") or "0"
    k = len(s)
    n = dot_pos - first_sig + exp  # valor = 0.s × 10^n
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    e = n - 1
    exp_sign = "+" if e >= 0 else "-"
    mant_part = s[0] if k == 1 else s[0] + "." + s[1:]
    return f"{sign}{mant_part}e{exp_sign}{abs(e)}"


def _serialize(value: Any, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if value > BINARY64_MAX_INT or value < BINARY64_MIN_INT:
            raise JcsError(
                f"entero {value} fuera del rango interoperable de "
                "IEEE 754 binary64 (±(2^53-1)): codifícalo como cadena decimal"
            )
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_es6_number(value))
    elif isinstance(value, str):
        out.append(_escape_string(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        # Claves: orden lexicográfico por unidades de código UTF-16;
        # UTF-16BE preserva ese orden para cadenas bien formadas.
        keys = sorted(value.keys(), key=lambda k: _key_order(k))
        out.append("{")
        for i, k in enumerate(keys):
            if i:
                out.append(",")
            if not isinstance(k, str):
                raise JcsError(f"clave no textual en objeto: {k!r}")
            out.append(_escape_string(k))
            out.append(":")
            _serialize(value[k], out)
        out.append("}")
    else:
        raise JcsError(f"tipo no serializable en JCS: {type(value).__name__}")


def _key_order(k: Any) -> bytes:
    if not isinstance(k, str):
        raise JcsError(f"clave no textual en objeto: {k!r}")
    return k.encode("utf-16-be", "surrogatepass") if _has_surrogate(k) else k.encode("utf-16-be")


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def dumps(value: Any) -> str:
    """Serializa `value` a su forma canónica RFC 8785 (texto JSON)."""
    out: list = []
    _serialize(value, out)
    return "".join(out)


def dumps_bytes(value: Any) -> bytes:
    """Serializa a bytes UTF-8 canónicos (sin BOM): la entrada exacta de firma."""
    return dumps(value).encode("utf-8")


def canonical_bytes(value: Any) -> bytes:
    """Alias semántico para firmas: `dumps_bytes` con nombre de dominio claro."""
    return dumps_bytes(value)
