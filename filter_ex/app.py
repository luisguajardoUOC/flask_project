import subprocess
import os
import signal
import json
from flask import Flask, jsonify, request

app = Flask(__name__)

# Variable global para almacenar el proceso del proxy
proxy_process = None
# Lista de webs a bloquear (puedes cambiar esta lista dinámicamente)
blocked_websites = [
    "campus.uoc.edu",
    "aula.uoc.edu",
    "www.edu4java.com"
]

# Ruta para iniciar el proxy
@app.route('/start_proxy', methods=['GET'])
def start_proxy():
    global proxy_process

    # Si el proxy ya está corriendo, no lo iniciamos de nuevo
    if proxy_process is not None:
        return jsonify({"message": "Proxy already running"}), 400
    
    # Guardar la lista de webs bloqueadas en un archivo JSON
    #blocked_websites_file = 'blocked_websites.json'
    #with open(blocked_websites_file, 'w') as f:
    #    json.dump(blocked_websites, f)

    # Iniciar el proxy usando subprocess
    try:
        proxy_process = subprocess.Popen(
            ['mitmdump', '--listen-port', '8080', '--ssl-insecure', '-s', 'filter_proxy2.py '],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        #for stdout_line in iter(proxy_process.stdout.readline, ""):
        #        print(stdout_line.strip())
        #proxy_process.stdout.close()
        # Leer la salida completa del proxy cuando termine       

        return jsonify({"message": "Proxy started successfully"}), 200
    except Exception as e:
        return jsonify({"message": f"Failed to start proxy: {str(e)}"}), 500

# Ruta para detener el proxy
@app.route('/stop_proxy', methods=['GET'])
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

#Ruta para agregar webs a bloquear
@app.route('/add_blocked_site', methods=['POST'])
def add_blocked_site():    
    data = request.get_json()
     # Verificar si se recibieron los datos y si tienen los campos necesarios
    if not data:
        return jsonify({"message": "No JSON data found in request"}), 400
    #verificar que el JSON esté completo
    if not data.get('url') or not data.get('category') or not data.get('reason'):
        return jsonify({"message": "Invalid data. Fields 'url', 'category', and 'reason' are required."}), 400

    try:
        with open("blocked_websites.json",  'r') as f:
            blocked_websites = json.load(f)
    except FileNotFoundError:
        blocked_websites = []
     # Verificar si el sitio ya está en la lista
    for site in blocked_websites:
        if site['url'] == data['url']:
            return jsonify({"message": "Website already blocked"}), 400
    # Agregar la nueva entrada
    blocked_websites.append(data)
    # guardar la lista nuev en el archivo JSON
    with open("blocked_websites.json", 'w') as f:
        json.dump(blocked_websites, f)

    return jsonify({"message": f"Added {data} to blocked list."}), 200

@app.route('/add_authorized_sites', methods=['POST'])
def add_authorized_sites():
    global blocked_websites
    new_sites = request.json.get('sites')
    if new_sites:
        blocked_websites.extend(new_sites)
        return jsonify({"message": f"Added {new_sites} to authorized list."}), 200
    return jsonify({"message": "Invalid input."}), 400
# Ruta para listar las webs bloqueadas
@app.route('/list_blocked_sites', methods=['GET'])
def list_blocked_sites():
    global blocked_websites
    return jsonify({"blocked_websites": blocked_websites}), 200

if __name__ == '__main__':
    app.run(debug=True)
