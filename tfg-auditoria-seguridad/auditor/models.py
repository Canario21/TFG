"""Modelos de datos de la herramienta.

Define las estructuras que circulan por el pipeline: la regla del catálogo
(`Rule`, con su comprobación y sus acciones de cambio de estado) y el
resultado de evaluar una regla (`CheckResult`). Se usan dataclasses para que
la carga desde YAML sea directa y el código quede autodescriptivo.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Check:
    """Comprobación que determina si una regla se cumple.

    `esperado` es siempre el valor SEGURO de referencia. El evaluador marca la
    regla como INCUMPLE cuando el valor real del sistema se aparta de él.
    """
    tipo: str                         # uno de constants.TIPOS_CHECK
    esperado: Any = None              # valor seguro de referencia
    parametro: Optional[str] = None   # clave a consultar (sysctl, sshd, puerto, ruta, servicio)
    protocolo: Optional[str] = None   # tcp | udp, solo para tipo 'port'
    comando: Optional[str] = None     # solo para tipo 'command'
    operador: str = "igual"           # igual | contiene | no_contiene | regex | menor_igual | mayor_igual


@dataclass
class Accion:
    """Acción que modifica el estado del sistema (remediación o rollback)."""
    comando: str
    requiere_root: bool = True
    reversible: bool = True


@dataclass
class Rule:
    """Una regla del catálogo, cargada desde los YAML de categoría."""
    id: str
    titulo: str
    categoria: str
    severidad: str                    # baja | media | alta | critica
    check: Check
    remediacion: Optional[Accion] = None
    rollback: Optional[Accion] = None
    descripcion: str = ""


@dataclass
class CheckResult:
    """Resultado de evaluar una regla sobre el sistema."""
    rule_id: str
    categoria: str
    severidad: str
    estado: str                       # constants.CUMPLE | INCUMPLE | NO_EVALUABLE
    valor_obtenido: Optional[str] = None
    valor_esperado: Optional[str] = None
    detalle: str = ""
    peso: int = 0                     # contribución a la métrica S cuando incumple


@dataclass
class AuditReport:
    """Conjunto del resultado de una ejecución en modo audit."""
    alcance: List[str] = field(default_factory=list)   # categorías evaluadas
    sockets: List[Any] = field(default_factory=list)   # puertos descubiertos
    resultados: List[CheckResult] = field(default_factory=list)
    superficie: int = 0               # métrica S total
