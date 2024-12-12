from cx_Freeze import setup, Executable
import sys

# Opciones de construcción
build_exe_options = {
    "packages": [
        "os",
        "pymysql",
    ],
    "includes": ["pymysql"],
    "include_files": [
        ("static/assets", "static/assets"),
        ("routes", "routes"),
        ("filter_proxy.py", "filter_proxy.py"),
        ("db_queries.py", "db_queries.py"),
        ("db.py", "db.py"),
        ("json_utils.py", "json_utils.py"),
    ],
}

# Opciones del ejecutable
base = None
if sys.platform == "win32":
    base = "Console"  # Cambiar a "Console" si necesitas la consola activa

executables = [
    Executable(
        'app.py',  # Archivo principal
        base=base,
        target_name='app.exe',  # Nombre del ejecutable
    )
]

# Configuración de cx_Freeze
setup(
    name='MiAplicacion',
    version='1.0',
    description='Proyecto Flask con MySQL',
    options={'build_exe': build_exe_options},
    executables=executables,
)
