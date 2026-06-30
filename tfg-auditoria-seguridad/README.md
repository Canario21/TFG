# tfg-auditoria-seguridad

Herramienta de auditoría y *hardening* de servidores Linux desarrollada como
parte del Trabajo de Fin de Grado «Automatización de auditorías de seguridad en
equipos mediante escaneo de puertos y *hardening*» (Grado en Ingeniería de
Tecnologías de la Telecomunicación, ULPGC).

La herramienta descubre los servicios en escucha de la propia máquina con `ss`,
evalúa un catálogo de reglas basado en CIS y NIST, calcula una métrica de
superficie de ataque y aplica una remediación reversible de las desviaciones
detectadas.

## Requisitos

- Python 3.8 o superior.
- PyYAML (`sudo apt install python3-yaml`).
- Sistema objetivo Linux con `ss`, `sysctl`, `systemctl`, `stat` y `sshd`.
- Privilegios de root para la auditoría completa y para los modos `remediate`
  y `rollback`.

## Estructura

```
auditor/        Paquete Python con la lógica de la herramienta
  scanner.py    Descubrimiento local de puertos con ss
  loader.py     Carga y validación del catálogo
  evaluator.py  Evaluación de las reglas (seis tipos de check)
  metrics.py    Cálculo de la superficie de ataque S
  remediator.py Remediación y rollback
  reporter.py   Informe JSON
  pipeline.py   Orquestación de los modos
  cli.py        Interfaz de línea de órdenes
catalog/        Un fichero YAML por categoría (43 reglas) + weights.yaml
lab/            Aprovisionamiento del escenario base vulnerable
```

## Uso

```bash
# Auditoría completa (informe por pantalla)
sudo python3 -m auditor audit

# Auditoría con informe en fichero JSON
sudo python3 -m auditor audit -o informe.json

# Auditoría acotada a una o varias categorías
sudo python3 -m auditor audit --category SSH --category NET

# Remediación de las reglas incumplidas (registra el estado para el rollback)
sudo python3 -m auditor remediate -o remediacion.json

# Reversión de la última remediación
sudo python3 -m auditor rollback
```

## Catálogo

43 reglas organizadas en siete categorías: servicios (SRV), red (NET), acceso
remoto SSH, cuentas (ACC), permisos (PERM), registro (LOG) y actualizaciones
(UPD). Cada regla revierte una recomendación del *CIS Ubuntu Linux 24.04 LTS
Benchmark* bajo los principios de la guía NIST SP 800-123. Las reglas son datos
en YAML, de modo que el catálogo puede ampliarse sin tocar el código.

## Métrica de superficie

La superficie de ataque S combina dos dimensiones:

```
S = (puertos accesibles desde la red × peso)  +  (reglas incumplidas × severidad)
```

Los pesos de severidad (1, 3, 7, 15) son no lineales, por analogía con CVSS v3.
La herramienta informa de S antes y después de la remediación, lo que permite
cuantificar la reducción de la superficie.

## Laboratorio

El directorio `lab/` contiene `vulnerable.sh`, el script que aprovisiona el
escenario base inseguro sobre el que se valida la herramienta. Debe ejecutarse
como root en una máquina virtual desechable, nunca en un sistema de producción.
