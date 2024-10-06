
"""
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    role ENUM('student', 'teacher', 'public') NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocked_websites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(255),
    reason VARCHAR(255)
);

CREATE TABLE rules_by_ip (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    userIP VARCHAR(45) NOT NULL,
    blocked_website_id INT,
    FOREIGN KEY (blocked_website_id) REFERENCES blocked_websites(id)
);

CREATE TABLE rules_by_role (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(50) NOT NULL,
    role VARCHAR(50) NOT NULL,
    blocked_website_id INT,
    FOREIGN KEY (blocked_website_id) REFERENCES blocked_websites(id)
);

CREATE TABLE malicious_keywords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    keyword VARCHAR(255) NOT NULL
);

CREATE TABLE history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    url VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL, -- 'allowed' o 'blocked'
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
"""

import subprocess
import os
import signal
import json
import logging
import mysql.connector
from flask import Flask, jsonify, request
from db import get_db_connection #importar a función rchivo db.py

app = Flask(__name__)
# Configuración del logging
logging.basicConfig(level=logging.DEBUG) 
# Para asegurar que Flask loguee en la consola
app.logger.setLevel(logging.DEBUG)

# Ruta para iniciar el proxy
@app.route('/start_proxy', methods=['GET'])
def start_proxy():
    global proxy_process

    # Si el proxy ya está corriendo, no lo iniciamos de nuevo
    if proxy_process is not None:
        return jsonify({"message": "Proxy already running"}), 400   
   

    # Iniciar el proxy usando subprocess
    try:
        proxy_process = subprocess.Popen(
            ['mitmdump', '--listen-port', '8080', '--ssl-insecure', '-s', 'filter_proxy.py '],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        for stdout_line in iter(proxy_process.stdout.readline, ""):
                print(stdout_line.strip())
        proxy_process.stdout.close()
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
    data = request.json
    url = data.get('url')
    category = data.get('type')
    reason = data.get('reason')

    if not url or not category or not reason:
        return jsonify({"error": "Faltan datos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verificar si el sitio ya está en la lista
        cursor.execute("SELECT id FROM blocked_websites WHERE url = %s", (url,))
        site = cursor.fetchone()

        if site:
            return jsonify({"message": "Website already blocked"}), 400

        # Insertar el nuevo sitio bloqueado
        cursor.execute("INSERT INTO blocked_websites (url, type, reason) VALUES (%s, %s, %s)", 
                       (url, category, reason))
        conn.commit()
        return jsonify({"message": f"Added {url} to blocked list."}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()



@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    username = data.get('username')
    userIP = data.get('ip_address')
    role = data.get('role')
    # Comprobar si faltan los datos y generar el mensaje de error adecuado
    
    if not username or not userIP or not role:
       return jsonify({"error": "Faltan datos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insertar el nuevo usuario
        cursor.execute("INSERT INTO users (username, ip_address, role) VALUES (%s, %s, %s)",
                       (username, userIP, role))
        conn.commit()
        return jsonify({"message": "Usuario añadido correctamente"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/add_rule', methods=['POST'])
def add_rule():
    data = request.json
    action = data.get('action')
    url = data.get('url')
    type = data.get('type')
    reason = data.get('reason')
    userIP = data.get('userIP')
    role = data.get('role')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Paso 1: Verificar o insertar la URL en blocked_websites
        cursor.execute("SELECT id FROM blocked_websites WHERE url = %s", (url,))
        website = cursor.fetchone()

        if website:
            blocked_website_id = website[0]
        else:
            cursor.execute("INSERT INTO blocked_websites (url, type, reason) VALUES (%s, %s, %s)", 
                           (url, type, reason))
            conn.commit()
            blocked_website_id = cursor.lastrowid

        # Paso 2: Insertar la regla en la tabla correspondiente
        if userIP:
            # Insertar en rules_by_ip
            cursor.execute("INSERT INTO rules_by_ip (action, userIP, blocked_website_id) VALUES (%s, %s, %s)", 
                           (action, userIP, blocked_website_id))
        elif role:
            # Insertar en rules_by_role
            cursor.execute("INSERT INTO rules_by_role (action, role, blocked_website_id) VALUES (%s, %s, %s)", 
                           (action, role, blocked_website_id))

        conn.commit()
        return jsonify({"message": "Regla añadida correctamente"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/edit_rule', methods=['POST'])
def edit_rule():
    data = request.json
    action = data.get('action')
    url = data.get('url')
    type = data.get('type')
    reason = data.get('reason')
    userIP = data.get('userIP')
    role = data.get('role')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verificar o insertar la URL en blocked_websites
        cursor.execute("SELECT id FROM blocked_websites WHERE url = %s", (url,))
        website = cursor.fetchone()

        if website:
            blocked_website_id = website[0]
        else:
            cursor.execute("INSERT INTO blocked_websites (url, type, reason) VALUES (%s, %s, %s)",
                           (url, type, reason))
            conn.commit()
            blocked_website_id = cursor.lastrowid

        # Actualizar en rules_by_ip si userIP está presente
        if userIP:
            # Dividir las IPs por coma en caso de recibir múltiples IPs
            user_ips = [ip.strip() for ip in userIP.split(",")]
            # Obtener las IPs actuales de la base de datos
            cursor.execute("SELECT userIP FROM rules_by_ip WHERE blocked_website_id = %s AND action = %s", (blocked_website_id, action))
            current_ips = [row[0] for row in cursor.fetchall()]
            # Eliminar las IPs que están en la base de datos pero no en el nuevo JSON
            for ip in current_ips:
                if ip not in user_ips:
                    cursor.execute("DELETE FROM rules_by_ip WHERE blocked_website_id = %s AND userIP = %s AND action = %s", 
                           (blocked_website_id, ip, action))


            for ip in user_ips:
                # Verificar si ya existe una entrada con el mismo blocked_website_id y userIP
                cursor.execute("""
                    SELECT userIP FROM rules_by_ip 
                    WHERE blocked_website_id = %s AND userIP = %s
                """, (blocked_website_id, ip))
                current_userIP = cursor.fetchone()            
                logging.info(current_userIP)

                if current_userIP:
                    # Solo actualizar el action si la IP ya existe
                    cursor.execute("""
                        UPDATE rules_by_ip 
                        SET action = %s
                        WHERE blocked_website_id = %s AND userIP = %s
                    """, (action, blocked_website_id, ip))
                else:
                    # Agregar una nueva entrada para una combinación nueva de blocked_website_id y userIP
                    cursor.execute("""
                        INSERT INTO rules_by_ip (action, userIP, blocked_website_id)
                        VALUES (%s, %s, %s)
                    """, (action, ip, blocked_website_id))

        # Verificar si el role ha cambiado y actualizar en rules_by_role
        elif role:
            cursor.execute("""
                SELECT role FROM rules_by_role 
                WHERE blocked_website_id = %s
            """, (blocked_website_id,))
            current_role = cursor.fetchone()

            if current_role and current_role[0] != role:
                # Actualizar tanto el role como el action si el role es diferente
                cursor.execute("""
                    UPDATE rules_by_role 
                    SET action = %s, role = %s
                    WHERE blocked_website_id = %s
                """, (action, role, blocked_website_id))
            else:
                # Solo actualizar el action si el role no ha cambiado
                cursor.execute("""
                    UPDATE rules_by_role 
                    SET action = %s
                    WHERE blocked_website_id = %s
                """, (action, blocked_website_id))

        conn.commit()
        return jsonify({"message": "Regla editada correctamente"}), 200

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

    finally:
        # Consumir cualquier resultado pendiente antes de cerrar el cursor
        try:
            if cursor:
                cursor.fetchall()
        except mysql.connector.errors.InterfaceError:
            pass  # Si no hay más resultados, esto no causará un error
        if cursor:
            cursor.close()
        if conn:
            conn.close()



@app.route('/apply_rules', methods=['GET'])
def apply_rules():
    userIP = request.args.get('userIP')

    if not userIP:
        return jsonify({"error": "Falta la IP del usuario"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Buscar reglas basadas en la IP del usuario
        cursor.execute("SELECT bw.url FROM rules_by_ip rip JOIN blocked_websites bw ON rip.blocked_website_id = bw.id WHERE rip.userIP = %s", (userIP,))
        ip_rules = cursor.fetchall()

        if ip_rules:
            return jsonify({"message": "Bloqueado por IP", "urls_bloqueadas": ip_rules}), 403

        # Obtener el rol del usuario
        cursor.execute("SELECT role FROM users WHERE userIP = %s", (userIP,))
        user = cursor.fetchone()

        if user:
            role = user[0]
            # Buscar reglas basadas en el rol del usuario
            cursor.execute("SELECT bw.url FROM rules_by_role rbr JOIN blocked_websites bw ON rbr.blocked_website_id = bw.id WHERE rbr.role = %s", (role,))
            role_rules = cursor.fetchall()

            if role_rules:
                return jsonify({"message": f"Bloqueado por rol: {role}", "urls_bloqueadas": role_rules}), 403

        return jsonify({"message": "Acceso permitido"}), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()



@app.route('/add_keyword', methods=['POST'])
def add_keyword():
    data = request.json
    keyword = data.get('keyword')

    if not keyword:
        return jsonify({"error": "Falta la palabra clave"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO malicious_keywords (keyword) VALUES (%s)", (keyword,))
        conn.commit()
        return jsonify({"message": "Palabra clave añadida correctamente"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)