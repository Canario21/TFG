"""Evaluación de las reglas del catálogo sobre el sistema local.

Para cada regla ejecuta su comprobación según el tipo de check, obtiene el
valor real del sistema y lo compara con el valor seguro de referencia. Devuelve
un CheckResult con uno de tres estados: CUMPLE, INCUMPLE o NO_EVALUABLE. Este
último se asigna cuando la comprobación no puede realizarse (binario ausente,
fichero inexistente o salida inesperada) y nunca se confunde con CUMPLE.

Para una auditoría rápida desde la línea de órdenes:

    python3 -m auditor.evaluator
"""

from __future__ import annotations

import os
import re
from typing import List, Optional, Set, Tuple

from . import constants
from .executor import LocalExecutor
from .models import Check, CheckResult, Rule
from .scanner import descubrir


class Evaluator:
    """Aplica las comprobaciones del catálogo y produce los resultados."""

    def __init__(self, pesos: Optional[dict] = None, executor: Optional[LocalExecutor] = None):
        self.pesos = pesos or dict(constants.PESOS_SEVERIDAD)
        self.executor = executor or LocalExecutor()
        self._puertos: Set[Tuple[str, int]] = set()
        self.sockets: list = []   # sockets descubiertos en la última evaluación

    # --- API pública --------------------------------------------------------
    def evaluar(self, reglas: List[Rule]) -> List[CheckResult]:
        """Descubre los puertos una vez y evalúa todas las reglas."""
        self.sockets = descubrir()
        self._puertos = {(s.protocolo, s.puerto) for s in self.sockets}
        return [self._evaluar_regla(r) for r in reglas]

    # --- Despacho por tipo de check ----------------------------------------
    def _evaluar_regla(self, regla: Rule) -> CheckResult:
        despacho = {
            constants.CHECK_PORT: self._check_port,
            constants.CHECK_SYSCTL: self._check_sysctl,
            constants.CHECK_FILE_MODE: self._check_file_mode,
            constants.CHECK_SERVICE: self._check_service,
            constants.CHECK_SSHD: self._check_sshd,
            constants.CHECK_COMMAND: self._check_command,
        }
        try:
            estado, obtenido, esperado, detalle = despacho[regla.check.tipo](regla)
        except Exception as exc:  # red de seguridad: nada aborta la auditoría
            estado, obtenido, esperado, detalle = (
                constants.NO_EVALUABLE, None, None, f"error inesperado: {exc}"
            )
        peso = self.pesos.get(regla.severidad, 0) if estado == constants.INCUMPLE else 0
        return CheckResult(
            rule_id=regla.id,
            categoria=regla.categoria,
            severidad=regla.severidad,
            estado=estado,
            valor_obtenido=obtenido,
            valor_esperado=esperado,
            detalle=detalle,
            peso=peso,
        )

    # --- Comprobaciones concretas ------------------------------------------
    def _check_port(self, regla: Rule):
        proto = (regla.check.protocolo or "tcp").lower()
        puerto = int(regla.check.parametro)
        escuchando = (proto, puerto) in self._puertos
        estado = constants.INCUMPLE if escuchando else constants.CUMPLE
        obtenido = "en escucha" if escuchando else "cerrado"
        return estado, obtenido, "cerrado", f"{proto}/{puerto}"

    def _check_sysctl(self, regla: Rule):
        param = regla.check.parametro
        esperado = str(regla.check.esperado)
        res = self.executor.ejecutar(["sysctl", "-n", param])
        if not res.encontrado:
            return constants.NO_EVALUABLE, None, esperado, "sysctl no disponible"
        if not res.ok:
            return constants.NO_EVALUABLE, None, esperado, res.error or "parámetro ausente"
        obtenido = res.salida.split()[0] if res.salida else ""
        estado = constants.CUMPLE if obtenido == esperado else constants.INCUMPLE
        return estado, obtenido, esperado, param

    def _check_file_mode(self, regla: Rule):
        ruta = regla.check.parametro
        esperado = str(regla.check.esperado)
        res = self.executor.ejecutar(["stat", "-c", "%a", ruta])
        if not res.encontrado:
            return constants.NO_EVALUABLE, None, esperado, "stat no disponible"
        if not res.ok:
            return constants.NO_EVALUABLE, None, esperado, "fichero inexistente"
        actual = int(res.salida, 8)
        seguro = int(esperado, 8)
        # Incumple si concede algún bit de permiso que el modo seguro no contempla.
        exceso = actual & ~seguro
        estado = constants.INCUMPLE if exceso else constants.CUMPLE
        return estado, oct(actual)[2:], esperado, ruta

    def _check_service(self, regla: Rule):
        svc = regla.check.parametro
        esperado = str(regla.check.esperado).lower()   # active | inactive
        res = self.executor.ejecutar(["systemctl", "is-active", svc])
        if not res.encontrado:
            return constants.NO_EVALUABLE, None, esperado, "systemctl no disponible"
        obtenido = res.salida or "unknown"
        estado = constants.CUMPLE if obtenido == esperado else constants.INCUMPLE
        return estado, obtenido, esperado, svc

    def _check_sshd(self, regla: Rule):
        opcion = regla.check.parametro.lower()
        # sshd suele estar en /usr/sbin, que no siempre está en el PATH heredado
        # por el subproceso; se usa la ruta absoluta cuando existe.
        binario = "/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else "sshd"
        res = self.executor.ejecutar([binario, "-T"])
        if not res.encontrado:
            return constants.NO_EVALUABLE, None, str(regla.check.esperado), "sshd no disponible"
        if not res.ok:
            return constants.NO_EVALUABLE, None, str(regla.check.esperado), res.error or "sshd -T falló"
        valor = None
        for linea in res.salida.splitlines():
            if linea.lower().startswith(opcion + " "):
                valor = linea.split(None, 1)[1].strip()
                break
        if valor is None:
            return constants.NO_EVALUABLE, None, str(regla.check.esperado), f"opción {opcion} ausente"
        estado = self._comparar(valor, regla.check)
        return estado, valor, str(regla.check.esperado), opcion

    def _check_command(self, regla: Rule):
        res = self.executor.ejecutar(regla.check.comando, shell=True)
        if not res.encontrado:
            return constants.NO_EVALUABLE, None, str(regla.check.esperado), "binario no disponible"
        obtenido = res.salida
        estado = self._comparar(obtenido, regla.check)
        return estado, obtenido, str(regla.check.esperado), regla.check.comando

    # --- Comparación genérica de valores -----------------------------------
    def _comparar(self, obtenido: str, check: Check) -> str:
        esperado = check.esperado
        op = check.operador
        o = obtenido.strip()
        if op == "igual":
            ok = o == str(esperado)
        elif op == "en_conjunto":
            ok = o in [str(x) for x in esperado]
        elif op == "contiene":
            ok = str(esperado) in o
        elif op == "no_contiene":
            prohibidos = esperado if isinstance(esperado, list) else [esperado]
            ok = all(str(p) not in o for p in prohibidos)
        elif op == "regex":
            ok = re.search(str(esperado), o) is not None
        elif op in ("menor_igual", "mayor_igual"):
            num = self._num(o)
            if num is None:
                return constants.NO_EVALUABLE
            ok = num <= float(esperado) if op == "menor_igual" else num >= float(esperado)
        else:
            return constants.NO_EVALUABLE
        return constants.CUMPLE if ok else constants.INCUMPLE

    @staticmethod
    def _num(texto: str) -> Optional[int]:
        m = re.match(r"-?\d+", texto.strip())
        return int(m.group()) if m else None


if __name__ == "__main__":
    import sys

    from .loader import cargar_catalogo, cargar_pesos

    directorio = sys.argv[1] if len(sys.argv) > 1 else "catalog"
    reglas = cargar_catalogo(directorio)
    pesos = cargar_pesos(directorio)
    resultados = Evaluator(pesos).evaluar(reglas)

    print(f"{'REGLA':10} {'ESTADO':12} {'PESO':>4}  OBTENIDO (ESPERADO)")
    for r in resultados:
        print(f"{r.rule_id:10} {r.estado:12} {r.peso:>4}  {r.valor_obtenido} ({r.valor_esperado})  [{r.detalle}]")
    incumplidas = [r for r in resultados if r.estado == constants.INCUMPLE]
    superficie = sum(r.peso for r in incumplidas)
    print(f"\n{len(incumplidas)}/{len(resultados)} reglas incumplidas · superficie expuesta = {superficie}")
