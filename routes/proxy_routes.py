import os
import signal
import subprocess
import threading
from db_queries import DatabaseQueries
from flask import Blueprint, jsonify, request

from json_utils import json_utils

proxy_bp = Blueprint('proxy', __name__)
proxy_process = None 
db_queries = DatabaseQueries()
json_utils = json_utils()
#def __init__(self):
#        self.db_queries = DatabaseQueries()
def stream_process_output(process):
    """Captura la salida de stdout y stderr en tiempo real y la imprime."""
    for line in process.stdout:
        print(line.strip())
# Ruta para iniciar el proxy
@proxy_bp .route('/start_proxy', methods=['GET'])
def start_proxy():
    global proxy_process

    # Si el proxy ya está corriendo, no lo iniciamos de nuevo
    if proxy_process is not None:
        return jsonify({"message": "Proxy already running"}), 400   
   

    # Iniciar el proxy usando subprocess
    try:
        proxy_process = subprocess.Popen(
            ['mitmdump', '--listen-port', '8080','--ssl-insecure', '-s', 'filter_proxy.py '],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        # Crear un hilo para capturar la salida de mitmdump en tiempo real
        threading.Thread(target=stream_process_output, args=(proxy_process,), daemon=True).start()

        return jsonify({"message": "Proxy started successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Failed to start proxy: {str(e)}"}), 500

# Ruta para detener el proxy
@proxy_bp .route('/stop_proxy', methods=['GET'])
def stop_proxy():
    global proxy_process

    # Si no hay un proceso corriendo, no hacemos nada
    if proxy_process is None:
        return jsonify({"message": "No proxy is running"}), 400

    # Detener el proceso del proxy
    try:
        os.kill(proxy_process.pid, signal.SIGTERM)  # Enviar señal para detener el proceso
        proxy_process = None  # Resetear la variable del proceso
        return jsonify({"message": "Proxy stopped successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Failed to stop proxy: {str(e)}"}), 500

@proxy_bp .route('/reload_proxy', methods=['GET'])
def reload_proxy():
    # Llamar a la función stop_proxy para detener el proxy
    stop_response = stop_proxy()
    stop_status_code = stop_response[1]

    if stop_status_code != 200:
        return jsonify({"message": "Failed to stop proxy for reload"}), stop_status_code

    # Llamar a la función start_proxy para iniciar nuevamente el proxy
    start_response = start_proxy()
    start_status_code = start_response[1]

    if start_status_code == 200:
        return jsonify({"message": "Proxy reloaded successfully"}), 200
    else:
        return jsonify({"message": "Failed to start proxy after reload"}), start_status_code

@proxy_bp .route('/proxy_status', methods=['GET'])
def proxy_status():
    global proxy_process
    if proxy_process is not None:
        return jsonify({"message": "Proxy is running"}), 200
    else:
        return jsonify({"message": "Proxy is not running"}), 400