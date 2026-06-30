"""Constantes compartidas por la herramienta.

Reúne en un único punto los estados de evaluación, los modos de ejecución y
los pesos por severidad, de modo que el resto de módulos no contengan valores
"mágicos" dispersos.
"""

# --- Estados posibles tras evaluar una regla -------------------------------
# Se distingue explícitamente NO_EVALUABLE de CUMPLE para no dar por buena una
# regla que no ha podido comprobarse (binario ausente, fichero inexistente,
# salida inesperada del comando).
CUMPLE = "cumple"
INCUMPLE = "incumple"
NO_EVALUABLE = "no_evaluable"

# --- Modos de ejecución de la herramienta ----------------------------------
MODO_AUDIT = "audit"
MODO_REMEDIATE = "remediate"
MODO_ROLLBACK = "rollback"

# --- Pesos no lineales por severidad ---------------------------------------
# La progresión 1, 3, 7, 15 es deliberadamente no lineal, por analogía con la
# escala de CVSS v3: una desviación crítica pesa mucho más que varias bajas.
# El catálogo puede sobrescribir estos valores mediante catalog/weights.yaml.
PESOS_SEVERIDAD = {
    "baja": 1,
    "media": 3,
    "alta": 7,
    "critica": 15,
}

# Peso uniforme por puerto en escucha accesible desde la red (término de
# exposición de la métrica S). Configurable en catalog/weights.yaml.
PESO_PUERTO_EXPUESTO = 2

# Categoría del catálogo que cubre los servicios/puertos en escucha. El término
# de exposición de la métrica S solo se contabiliza cuando esta categoría está
# en el alcance evaluado, de modo que una auditoría acotada mide solo lo suyo.
CATEGORIA_PUERTOS = "SRV"

# Tipos de comprobación admitidos en el campo `check.tipo` del catálogo.
CHECK_PORT = "port"            # puerto en escucha (lo aporta scanner.py)
CHECK_SYSCTL = "sysctl"        # parámetro del núcleo
CHECK_FILE_MODE = "file_mode"  # permisos octales de un fichero
CHECK_SERVICE = "service"      # estado de un servicio systemd
CHECK_SSHD = "sshd"            # opción efectiva de sshd (sshd -T)
CHECK_COMMAND = "command"      # comando genérico con comparación del resultado

TIPOS_CHECK = {
    CHECK_PORT, CHECK_SYSCTL, CHECK_FILE_MODE,
    CHECK_SERVICE, CHECK_SSHD, CHECK_COMMAND,
}
