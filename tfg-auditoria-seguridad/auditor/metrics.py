"""Cálculo de la métrica de superficie de ataque S.

S combina dos dimensiones, según el diseño del capítulo 3:

  - Exposición de red: cada puerto en escucha accesible desde la red suma un
    peso uniforme. Los puertos enlazados solo a la interfaz de loopback no se
    cuentan aquí, porque no son alcanzables desde la red (es la diferencia que
    el escaneo externo no captaría).
  - Configuración: cada regla incumplida suma el peso de su severidad.

Un servicio inseguro accesible (por ejemplo Telnet) contribuye a las dos
dimensiones de forma deliberada: está expuesto y, además, está mal
configurado. Son dos propiedades distintas del mismo servicio.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from . import constants
from .models import CheckResult


@dataclass
class Superficie:
    """Resultado del cálculo de la métrica S."""
    exposicion: int       # término de puertos accesibles desde la red
    configuracion: int    # término de reglas incumplidas
    total: int            # S = exposicion + configuracion
    puertos_red: int      # nº de puertos (proto, puerto) accesibles desde la red


def calcular(
    sockets,
    resultados: List[CheckResult],
    peso_puerto: int = constants.PESO_PUERTO_EXPUESTO,
) -> Superficie:
    """Calcula la superficie S a partir de los puertos y los resultados."""
    # Exposición: puertos (protocolo, puerto) únicos accesibles desde la red.
    expuestos = {(s.protocolo, s.puerto) for s in sockets if not s.local}
    exposicion = len(expuestos) * peso_puerto

    # Configuración: suma de los pesos de las reglas incumplidas.
    configuracion = sum(
        r.peso for r in resultados if r.estado == constants.INCUMPLE
    )

    return Superficie(
        exposicion=exposicion,
        configuracion=configuracion,
        total=exposicion + configuracion,
        puertos_red=len(expuestos),
    )
