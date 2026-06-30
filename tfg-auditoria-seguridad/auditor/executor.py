"""Ejecución de comandos del sistema.

Concentra en un único punto (LocalExecutor) las llamadas a subprocess, de modo
que el evaluador y el remediador no las invoquen directamente. El resultado
distingue tres situaciones que el evaluador traduce después a estados: éxito,
fallo del comando (código de salida distinto de cero) y ausencia del binario.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import List, Union


@dataclass
class Resultado:
    """Resultado de ejecutar un comando."""
    ok: bool            # True si el comando terminó con código 0
    salida: str         # stdout, sin espacios sobrantes
    error: str          # stderr, sin espacios sobrantes
    codigo: int         # código de salida (-1 si no se pudo ejecutar)
    encontrado: bool    # False si el binario no está instalado


class LocalExecutor:
    """Ejecuta comandos en la propia máquina (modelo local con ss)."""

    def ejecutar(
        self,
        comando: Union[List[str], str],
        shell: bool = False,
        timeout: int = 30,
    ) -> Resultado:
        """Ejecuta `comando` y devuelve un Resultado.

        Con shell=False se pasa una lista de argumentos; con shell=True, una
        cadena que interpreta /bin/sh (necesario para las reglas cuyo check es
        una tubería). Captura las excepciones de subprocess y las convierte en
        un Resultado, sin propagar la excepción al pipeline.
        """
        try:
            proc = subprocess.run(
                comando,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return Resultado(False, "", "binario no encontrado", -1, encontrado=False)
        except subprocess.TimeoutExpired:
            return Resultado(False, "", "tiempo de espera agotado", -1, encontrado=True)
        return Resultado(
            ok=(proc.returncode == 0),
            salida=proc.stdout.strip(),
            error=proc.stderr.strip(),
            codigo=proc.returncode,
            encontrado=True,
        )
