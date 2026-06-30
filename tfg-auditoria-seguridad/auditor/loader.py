"""Carga y validación del catálogo de reglas desde ficheros YAML.

Cada categoría se define en un fichero independiente dentro de catalog/, con
una clave `categoria` y una lista `reglas`. Los errores de carga son
irrecuperables y abortan la ejecución (directorio inexistente o vacío, YAML
mal formado, regla incompleta, severidad inválida o IDs duplicados), de
acuerdo con el diseño de gestión de errores del capítulo 3.

Para inspeccionar el catálogo cargado:

    python3 -m auditor.loader
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

import yaml

from . import constants
from .models import Accion, Check, Rule


class ErrorCatalogo(Exception):
    """Error irrecuperable durante la carga del catálogo."""


CAMPOS_OBLIGATORIOS = ("id", "titulo", "severidad", "check")


def _construir_check(datos: dict, rule_id: str) -> Check:
    tipo = datos.get("tipo")
    if tipo not in constants.TIPOS_CHECK:
        raise ErrorCatalogo(f"La regla {rule_id} define un check.tipo inválido: {tipo!r}")
    return Check(
        tipo=tipo,
        esperado=datos.get("esperado"),
        parametro=datos.get("parametro"),
        protocolo=datos.get("protocolo"),
        comando=datos.get("comando"),
        operador=datos.get("operador", "igual"),
    )


def _construir_accion(datos: Optional[dict]) -> Optional[Accion]:
    if not datos:
        return None
    if "comando" not in datos:
        raise ErrorCatalogo("Una acción no define el campo obligatorio 'comando'")
    return Accion(
        comando=datos["comando"],
        requiere_root=datos.get("requiere_root", True),
        reversible=datos.get("reversible", True),
    )


def _construir_regla(datos: dict, categoria_fichero: Optional[str]) -> Rule:
    faltan = [c for c in CAMPOS_OBLIGATORIOS if c not in datos]
    if faltan:
        raise ErrorCatalogo(f"Regla incompleta {datos.get('id', '(sin id)')}: faltan {faltan}")
    categoria = datos.get("categoria", categoria_fichero)
    if not categoria:
        raise ErrorCatalogo(f"La regla {datos['id']} no tiene categoría")
    if datos["severidad"] not in constants.PESOS_SEVERIDAD:
        raise ErrorCatalogo(
            f"La regla {datos['id']} tiene una severidad inválida: {datos['severidad']!r}"
        )
    return Rule(
        id=datos["id"],
        titulo=datos["titulo"],
        categoria=categoria,
        severidad=datos["severidad"],
        check=_construir_check(datos["check"], datos["id"]),
        remediacion=_construir_accion(datos.get("remediacion")),
        rollback=_construir_accion(datos.get("rollback")),
        descripcion=datos.get("descripcion", ""),
    )


def cargar_catalogo(directorio: str) -> List[Rule]:
    """Lee todos los YAML de reglas de `directorio` y devuelve la lista de reglas."""
    if not os.path.isdir(directorio):
        raise ErrorCatalogo(f"El directorio del catálogo no existe: {directorio}")

    ficheros = [
        f for f in sorted(os.listdir(directorio))
        if f.endswith((".yml", ".yaml")) and f != "weights.yaml"
    ]
    if not ficheros:
        raise ErrorCatalogo(f"No se encontraron ficheros de reglas en {directorio}")

    reglas: List[Rule] = []
    origen: Dict[str, str] = {}
    for fichero in ficheros:
        ruta = os.path.join(directorio, fichero)
        try:
            with open(ruta, encoding="utf-8") as fh:
                contenido = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ErrorCatalogo(f"YAML mal formado en {fichero}: {exc}") from exc

        categoria_fichero = contenido.get("categoria")
        for datos in contenido.get("reglas", []):
            regla = _construir_regla(datos, categoria_fichero)
            if regla.id in origen:
                raise ErrorCatalogo(
                    f"ID duplicado {regla.id}: aparece en {fichero} y en {origen[regla.id]}"
                )
            origen[regla.id] = fichero
            reglas.append(regla)
    return reglas


def cargar_pesos(directorio: str) -> Dict[str, int]:
    """Carga los pesos por severidad; usa los de constants como respaldo."""
    ruta = os.path.join(directorio, "weights.yaml")
    if not os.path.isfile(ruta):
        return dict(constants.PESOS_SEVERIDAD)
    with open(ruta, encoding="utf-8") as fh:
        datos = yaml.safe_load(fh) or {}
    return {**constants.PESOS_SEVERIDAD, **datos.get("severidad", {})}


def cargar_peso_puerto(directorio: str) -> int:
    """Carga el peso uniforme por puerto expuesto; usa el de constants como respaldo."""
    ruta = os.path.join(directorio, "weights.yaml")
    if not os.path.isfile(ruta):
        return constants.PESO_PUERTO_EXPUESTO
    with open(ruta, encoding="utf-8") as fh:
        datos = yaml.safe_load(fh) or {}
    return int(datos.get("puerto_expuesto", constants.PESO_PUERTO_EXPUESTO))


if __name__ == "__main__":
    import sys

    directorio = sys.argv[1] if len(sys.argv) > 1 else "catalog"
    cargadas = cargar_catalogo(directorio)
    print(f"{len(cargadas)} reglas cargadas desde {directorio}/")
    conteo: Dict[str, int] = {}
    for r in cargadas:
        conteo[r.categoria] = conteo.get(r.categoria, 0) + 1
    for cat, n in sorted(conteo.items()):
        print(f"  {cat:5} {n:2} reglas")
