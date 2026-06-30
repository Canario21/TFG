"""Serialización del resultado de una ejecución a un informe JSON.

El informe se estructura en tres bloques, según el diseño del capítulo 3:
`scan` (puertos descubiertos), `audit` (resultado regla por regla) y `metrics`
(la superficie S y su desglose). El campo `alcance` registra qué categorías se
evaluaron, para no comparar después una S acotada con una global.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import List

from . import constants
from .metrics import Superficie
from .models import CheckResult


def construir_informe(
    modo: str,
    alcance: List[str],
    sockets,
    resultados: List[CheckResult],
    superficie: Superficie,
    version: str = "0.1.0",
) -> dict:
    """Construye el diccionario del informe listo para serializar."""
    return {
        "version": version,
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "modo": modo,
        "alcance": alcance,
        "scan": {
            "puertos": [
                {
                    "protocolo": s.protocolo,
                    "direccion": s.direccion,
                    "puerto": s.puerto,
                    "local": s.local,
                }
                for s in sorted(sockets, key=lambda x: (x.protocolo, x.puerto))
            ]
        },
        "audit": [
            {
                "id": r.rule_id,
                "categoria": r.categoria,
                "severidad": r.severidad,
                "estado": r.estado,
                "obtenido": r.valor_obtenido,
                "esperado": r.valor_esperado,
                "peso": r.peso,
                "detalle": r.detalle,
            }
            for r in resultados
        ],
        "metrics": {
            "superficie_total": superficie.total,
            "exposicion": superficie.exposicion,
            "configuracion": superficie.configuracion,
            "puertos_red": superficie.puertos_red,
            "reglas_incumplidas": sum(
                1 for r in resultados if r.estado == constants.INCUMPLE
            ),
            "reglas_no_evaluables": sum(
                1 for r in resultados if r.estado == constants.NO_EVALUABLE
            ),
            "reglas_evaluadas": len(resultados),
        },
    }


def serializar(informe: dict) -> str:
    """Devuelve el informe como texto JSON con sangría."""
    return json.dumps(informe, ensure_ascii=False, indent=2)


def escribir_json(informe: dict, ruta: str) -> None:
    """Escribe el informe en disco en formato JSON."""
    with open(ruta, "w", encoding="utf-8") as fh:
        fh.write(serializar(informe))
