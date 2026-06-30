"""Orquestación de los modos de ejecución.

Encadena las etapas (carga del catálogo, filtrado por alcance, descubrimiento,
evaluación, cálculo de la métrica y, según el modo, remediación o rollback) sin
estado compartido entre módulos. Las categorías válidas se derivan del catálogo
cargado en tiempo de ejecución, no de una lista fija en el código.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from . import constants, metrics, remediator, reporter
from .evaluator import Evaluator
from .loader import cargar_catalogo, cargar_peso_puerto, cargar_pesos
from .models import CheckResult, Rule


def _filtrar_por_alcance(
    reglas: List[Rule], categorias: Optional[List[str]]
) -> Tuple[List[Rule], List[str]]:
    """Filtra las reglas por categoría y devuelve también el alcance evaluado."""
    disponibles = {r.categoria for r in reglas}
    if not categorias:
        return reglas, sorted(disponibles)

    pedidas = {c.upper() for c in categorias}
    desconocidas = pedidas - disponibles
    if desconocidas:
        raise ValueError(
            f"Categoría(s) inexistente(s): {', '.join(sorted(desconocidas))}. "
            f"Disponibles: {', '.join(sorted(disponibles))}"
        )
    filtradas = [r for r in reglas if r.categoria in pedidas]
    return filtradas, sorted(pedidas)


def _evaluar(directorio: str, reglas: List[Rule], alcance: List[str]):
    """Evalúa las reglas y calcula la superficie. La exposición de puertos solo
    se contabiliza si la categoría de servicios está dentro del alcance."""
    evaluador = Evaluator(cargar_pesos(directorio))
    resultados = evaluador.evaluar(reglas)
    sockets = evaluador.sockets
    peso_puerto = (
        cargar_peso_puerto(directorio)
        if constants.CATEGORIA_PUERTOS in alcance
        else 0
    )
    superficie = metrics.calcular(sockets, resultados, peso_puerto)
    return resultados, sockets, superficie


def ejecutar_audit(directorio: str, categorias: Optional[List[str]] = None) -> dict:
    """Ejecuta una auditoría completa y devuelve el informe como diccionario."""
    reglas = cargar_catalogo(directorio)
    reglas, alcance = _filtrar_por_alcance(reglas, categorias)
    resultados, sockets, superficie = _evaluar(directorio, reglas, alcance)
    return reporter.construir_informe(
        constants.MODO_AUDIT, alcance, sockets, resultados, superficie
    )


def ejecutar_remediate(
    directorio: str,
    categorias: Optional[List[str]] = None,
    ruta_estado: str = "rollback_state.json",
) -> dict:
    """Audita, aplica la remediación de las reglas incumplidas y registra lo hecho."""
    reglas = cargar_catalogo(directorio)
    reglas, alcance = _filtrar_por_alcance(reglas, categorias)

    resultados_antes, _, superficie_antes = _evaluar(directorio, reglas, alcance)
    aplicadas = remediator.Remediator().remediar(reglas, resultados_antes)
    remediator.guardar_registro(aplicadas, ruta_estado)
    _, _, superficie_despues = _evaluar(directorio, reglas, alcance)

    return {
        "modo": constants.MODO_REMEDIATE,
        "alcance": alcance,
        "estado_guardado_en": ruta_estado,
        "acciones": [a.__dict__ for a in aplicadas],
        "resumen": {
            "aplicadas_ok": sum(1 for a in aplicadas if a.ok),
            "fallidas": sum(1 for a in aplicadas if not a.ok),
            "no_reversibles": sum(1 for a in aplicadas if not a.reversible),
            "superficie_antes": superficie_antes.total,
            "superficie_despues": superficie_despues.total,
        },
    }


def ejecutar_rollback(
    directorio: str, ruta_estado: str = "rollback_state.json"
) -> dict:
    """Lee el registro de remediación y revierte las acciones reversibles."""
    registro = remediator.cargar_registro(ruta_estado)
    reglas = cargar_catalogo(directorio)
    por_id = {r.id: r for r in reglas}
    revertidas = remediator.Remediator().revertir(por_id, registro)

    return {
        "modo": constants.MODO_ROLLBACK,
        "estado_leido_de": ruta_estado,
        "acciones": [a.__dict__ for a in revertidas],
        "resumen": {
            "revertidas_ok": sum(1 for a in revertidas if a.ok),
            "fallidas": sum(1 for a in revertidas if not a.ok),
        },
    }
