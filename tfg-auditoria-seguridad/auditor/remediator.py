"""Aplicación y reversión de las acciones de hardening.

El modo remediate ejecuta la acción de remediación de cada regla incumplida y
registra lo aplicado en un fichero de estado. El modo rollback lee ese registro
y ejecuta la acción inversa de cada remediación reversible, en orden inverso al
de aplicación.

Se distingue el éxito del fallo de cada comando: un código de salida distinto de
cero se registra como fallo y la acción no se da por aplicada. Las reglas no
reversibles (por ejemplo UPD-001, aplicar actualizaciones) se aplican pero se
marcan para que el rollback no intente revertirlas.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, List

from . import constants
from .executor import LocalExecutor
from .models import CheckResult, Rule


@dataclass
class AccionAplicada:
    """Registro de una acción de remediación o rollback ejecutada."""
    rule_id: str
    comando: str
    ok: bool
    reversible: bool
    error: str = ""


class Remediator:
    """Ejecuta las acciones de cambio de estado del sistema."""

    def __init__(self, executor=None):
        self.executor = executor or LocalExecutor()

    def remediar(self, reglas: List[Rule], resultados: List[CheckResult]) -> List[AccionAplicada]:
        """Aplica la remediación de cada regla incumplida que tenga una definida."""
        incumplidas = {r.rule_id for r in resultados if r.estado == constants.INCUMPLE}
        aplicadas: List[AccionAplicada] = []
        for regla in reglas:
            if regla.id not in incumplidas or regla.remediacion is None:
                continue
            res = self.executor.ejecutar(regla.remediacion.comando, shell=True)
            aplicadas.append(
                AccionAplicada(
                    rule_id=regla.id,
                    comando=regla.remediacion.comando,
                    ok=res.ok,
                    reversible=regla.remediacion.reversible,
                    error="" if res.ok else (res.error or f"código de salida {res.codigo}"),
                )
            )
        return aplicadas

    def revertir(self, reglas_por_id: Dict[str, Rule], registro: List[dict]) -> List[AccionAplicada]:
        """Revierte, en orden inverso, las remediaciones reversibles aplicadas con éxito."""
        revertidas: List[AccionAplicada] = []
        for entrada in reversed(registro):
            if not entrada.get("ok") or not entrada.get("reversible", True):
                continue  # no se revierte lo que falló ni lo marcado como no reversible
            regla = reglas_por_id.get(entrada.get("rule_id"))
            if regla is None or regla.rollback is None:
                continue
            res = self.executor.ejecutar(regla.rollback.comando, shell=True)
            revertidas.append(
                AccionAplicada(
                    rule_id=regla.id,
                    comando=regla.rollback.comando,
                    ok=res.ok,
                    reversible=True,
                    error="" if res.ok else (res.error or f"código de salida {res.codigo}"),
                )
            )
        return revertidas


def guardar_registro(aplicadas: List[AccionAplicada], ruta: str) -> None:
    """Persiste el registro de remediación para un posible rollback posterior."""
    datos = {
        "fecha": datetime.now().isoformat(timespec="seconds"),
        "acciones": [asdict(a) for a in aplicadas],
    }
    with open(ruta, "w", encoding="utf-8") as fh:
        json.dump(datos, fh, ensure_ascii=False, indent=2)


def cargar_registro(ruta: str) -> List[dict]:
    """Lee el registro de remediación; error si no existe o está corrupto."""
    if not os.path.isfile(ruta):
        raise FileNotFoundError(f"no existe registro de remediación en {ruta}")
    try:
        with open(ruta, encoding="utf-8") as fh:
            datos = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"registro de remediación corrupto en {ruta}: {exc}") from exc
    return datos.get("acciones", [])
