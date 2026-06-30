"""Interfaz de línea de órdenes de la herramienta.

Expone los tres modos de ejecución (audit, remediate, rollback) y los
parámetros comunes: directorio del catálogo, alcance por categoría, ruta del
informe JSON y fichero de estado para el rollback. Traduce los errores
irrecuperables en códigos de salida distintos de cero con un mensaje en la
salida de error.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import constants, pipeline, reporter
from .loader import ErrorCatalogo


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Auditoría y hardening de servidores Linux basada en ss, CIS y NIST.",
    )
    parser.add_argument(
        "modo",
        choices=[constants.MODO_AUDIT, constants.MODO_REMEDIATE, constants.MODO_ROLLBACK],
        help="modo de ejecución",
    )
    parser.add_argument(
        "--catalog", default="catalog",
        help="directorio del catálogo de reglas (por defecto: catalog)",
    )
    parser.add_argument(
        "--category", action="append", metavar="CAT",
        help="limita el alcance a una categoría; se puede repetir",
    )
    parser.add_argument(
        "--output", "-o", metavar="RUTA",
        help="ruta del informe JSON (por defecto: salida estándar)",
    )
    parser.add_argument(
        "--state", default="rollback_state.json", metavar="RUTA",
        help="fichero de estado para el rollback (por defecto: rollback_state.json)",
    )
    return parser


def _sin_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() != 0


def _resumen(informe: dict) -> str:
    """Línea de resumen para la salida de error según el modo."""
    if "metrics" in informe:
        m = informe["metrics"]
        return (f"S={m['superficie_total']} "
                f"({m['reglas_incumplidas']}/{m['reglas_evaluadas']} incumplidas, "
                f"{m['reglas_no_evaluables']} no evaluables)")
    r = informe.get("resumen", {})
    if informe.get("modo") == constants.MODO_REMEDIATE:
        return (f"{r.get('aplicadas_ok', 0)} aplicadas, {r.get('fallidas', 0)} fallidas, "
                f"{r.get('no_reversibles', 0)} no reversibles · "
                f"S {r.get('superficie_antes', '?')} -> {r.get('superficie_despues', '?')}")
    return f"{r.get('revertidas_ok', 0)} revertidas, {r.get('fallidas', 0)} fallidas"


def main(argv: Optional[List[str]] = None) -> int:
    args = construir_parser().parse_args(argv)

    # Los modos que modifican el sistema exigen root; auditar sin root solo avisa.
    if args.modo in (constants.MODO_REMEDIATE, constants.MODO_ROLLBACK):
        if _sin_root():
            print(f"El modo '{args.modo}' requiere privilegios de root.", file=sys.stderr)
            return 1
    elif _sin_root():
        print("Aviso: ejecutando sin root; algunas reglas pueden quedar como "
              "no_evaluable.", file=sys.stderr)

    try:
        if args.modo == constants.MODO_AUDIT:
            informe = pipeline.ejecutar_audit(args.catalog, args.category)
        elif args.modo == constants.MODO_REMEDIATE:
            informe = pipeline.ejecutar_remediate(args.catalog, args.category, args.state)
        else:
            informe = pipeline.ejecutar_rollback(args.catalog, args.state)
    except ErrorCatalogo as exc:
        print(f"Error de catálogo: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error de alcance o de estado: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"Error de rollback: {exc}", file=sys.stderr)
        return 1

    texto = reporter.serializar(informe)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(texto)
        print(f"Informe escrito en {args.output} · {_resumen(informe)}", file=sys.stderr)
    else:
        print(texto)
        print(_resumen(informe), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
