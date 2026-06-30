"""Descubrimiento local de puertos en escucha mediante ss.

Este módulo sustituye al escaneo de red externo (Nmap) del modelo anterior.
Consulta al núcleo los sockets en estado de escucha a través de `ss -tuln`,
sin generar tráfico de red, e incluye los servicios enlazados a la interfaz
de loopback que un escaneo externo no observaría (por ejemplo CUPS en
127.0.0.1:631).

Puede ejecutarse de forma aislada para inspeccionar el estado de un equipo:

    python3 -m auditor.scanner
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import List


@dataclass
class Socket:
    """Un socket en estado de escucha."""
    protocolo: str   # tcp | udp
    direccion: str   # dirección local (0.0.0.0, 127.0.0.1, ::, *)
    puerto: int

    @property
    def local(self) -> bool:
        """True si el servicio solo escucha en la interfaz de loopback.

        Cubre todo el rango 127.0.0.0/8, la dirección ::1 y los sockets con
        ámbito de loopback (sufijo %lo), como el resolutor local de systemd
        en 127.0.0.53.
        """
        return (
            self.direccion.startswith("127.")
            or self.direccion == "::1"
            or self.direccion.endswith("%lo")
        )


def _ejecutar_ss() -> str:
    """Invoca `ss -tuln` y devuelve su salida estándar.

    Lanza FileNotFoundError si ss no está disponible y CalledProcessError si
    el comando termina con error; el pipeline traduce ambos a NO_EVALUABLE.
    """
    resultado = subprocess.run(
        ["ss", "-tuln"],
        capture_output=True,
        text=True,
        check=True,
    )
    return resultado.stdout


def _parsear(salida: str) -> List[Socket]:
    """Convierte la salida de ss en una lista de sockets en escucha.

    Se omite la línea de cabecera y se toma la quinta columna (Local
    Address:Port), separando el puerto por la derecha para tolerar tanto
    direcciones IPv4 (0.0.0.0:22) como IPv6 ([::]:631) o comodines (*:21).
    """
    sockets: List[Socket] = []
    for linea in salida.splitlines()[1:]:
        campos = linea.split()
        if len(campos) < 5:
            continue
        protocolo = campos[0].lower()
        direccion, _, puerto = campos[4].rpartition(":")
        if not puerto.isdigit():
            continue
        direccion = direccion.strip("[]")        # [::] -> ::
        sockets.append(Socket(protocolo, direccion, int(puerto)))
    return sockets


def descubrir() -> List[Socket]:
    """Devuelve los sockets TCP/UDP en escucha en el sistema local."""
    return _parsear(_ejecutar_ss())


if __name__ == "__main__":
    encontrados = sorted(descubrir(), key=lambda s: (s.protocolo, s.puerto))
    print(f"{'PROTO':5} {'DIRECCIÓN':>17}  PUERTO   ÁMBITO")
    for s in encontrados:
        ambito = "local" if s.local else "red"
        print(f"{s.protocolo:5} {s.direccion:>17}  {s.puerto:<6}   {ambito}")
    print(f"\n{len(encontrados)} sockets en escucha")
