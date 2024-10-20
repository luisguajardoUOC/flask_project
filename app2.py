
"""
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    role ENUM('student', 'teacher', 'public') NOT NULL,
    userIP VARCHAR(45) NOT NULL,
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
CREATE TABLE `authorized_websites` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `url` varchar(255) NOT NULL,
 `description` text DEFAULT NULL,
 PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `users` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `username` varchar(255) NOT NULL,
 `role` enum('student','teacher','public') NOT NULL,
 `userIP` varchar(45) DEFAULT NULL,
 `created_at` timestamp NULL DEFAULT current_timestamp(),
 PRIMARY KEY (`id`),
 UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4;

CREATE TABLE `blocked_websites` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `url` varchar(255) NOT NULL,
 `type` varchar(255) DEFAULT NULL,
 `reason` varchar(255) DEFAULT NULL,
 PRIMARY KEY (`id`),
 UNIQUE KEY `url` (`url`)
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4;

CREATE TABLE `malicious_keywords` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `keyword` varchar(255) NOT NULL,
 PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE `rules_by_ip` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `action` varchar(50) NOT NULL,
 `userIP` varchar(45) NOT NULL,
 `blocked_website_id` int(11) DEFAULT NULL,
 `user_id` int(11) DEFAULT NULL,
 PRIMARY KEY (`id`),
 KEY `blocked_website_id` (`blocked_website_id`),
 KEY `fk_user_id` (`user_id`),
 CONSTRAINT `fk_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
 CONSTRAINT `rules_by_ip_ibfk_1` FOREIGN KEY (`blocked_website_id`) REFERENCES `blocked_websites` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=85 DEFAULT CHARSET=utf8mb4;

CREATE TABLE `rules_by_role` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `action` varchar(50) NOT NULL,
 `role` varchar(50) NOT NULL,
 `blocked_website_id` int(11) DEFAULT NULL,
 PRIMARY KEY (`id`),
 KEY `blocked_website_id` (`blocked_website_id`),
 CONSTRAINT `rules_by_role_ibfk_1` FOREIGN KEY (`blocked_website_id`) REFERENCES `blocked_websites` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=86 DEFAULT CHARSET=utf8mb4;
	
CREATE TABLE `history` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `user_id` int(11) DEFAULT NULL,
 `url` varchar(255) NOT NULL,
 `action` varchar(50) NOT NULL,
 `timestamp` timestamp NULL DEFAULT current_timestamp(),
 PRIMARY KEY (`id`),
 KEY `user_id` (`user_id`),
 CONSTRAINT `history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

import subprocess
import threading
import os
import signal
import json
import logging
import mysql.connector
from flask import Flask, jsonify, request
from flask_cors import CORS
from db import get_db_connection #importar a función rchivo db.py
# from collections import OrderedDict
from collections import defaultdict
from flask import Response
from db_queries import DatabaseQueries

app = Flask(__name__)
CORS(app)
# Configuración del logging

#logging.basicConfig(level=logging.INFO) 
#logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
# Para asegurar que Flask loguee en la consola

proxy_process = None 
db_queries = DatabaseQueries()
#def __init__(self):
#        self.db_queries = DatabaseQueries()
def stream_process_output(process):
    """Captura la salida de stdout y stderr en tiempo real y la imprime."""
    for line in process.stdout:
        print(line.strip())
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
        # Crear un hilo para capturar la salida de mitmdump en tiempo real
        threading.Thread(target=stream_process_output, args=(proxy_process,), daemon=True).start()

        #for stdout_line in iter(proxy_process.stdout.readline, ""):
        #        print(stdout_line.strip())
        # proxy_process.stdout.close()
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

@app.route('/reload_proxy', methods=['GET'])
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

@app.route('/proxy_status', methods=['GET'])
def proxy_status():
    global proxy_process
    if proxy_process is not None:
        return jsonify({"message": "Proxy is running"}), 200
    else:
        return jsonify({"message": "Proxy is not running"}), 400

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
    userIP = data.get('userIP')
    role = data.get('role')
    # Comprobar si faltan los datos y generar el mensaje de error adecuado
    
    if not username or not userIP or not role:
       return jsonify({"error": "Faltan datos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verificar si la IP ya existe en la base de datos
        cursor.execute("SELECT id FROM users WHERE userIP = %s", (userIP,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"error": "La IP ya está asignada a otro usuario"}), 400
        # Insertar el nuevo usuario
        cursor.execute("INSERT INTO users (username, userIP, role) VALUES (%s, %s, %s)",
                       (username, userIP, role))
        conn.commit()
        return jsonify({"message": "Usuario añadido correctamente"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()
@app.route('/edit_user', methods=['POST'])
def edit_user():
    data = request.json
    id = data.get('id')
    username = data.get('username')
    userIP = data.get('userIP')
    role = data.get('role')

    if not id or not username or not userIP or not role:
        return jsonify({"error": "Faltan datos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()    

    try:
        # Verificar si la IP ya está asignada a otro usuario (exceptuando el mismo usuario)
        cursor.execute("SELECT id FROM users WHERE userIP = %s AND id != %s", (userIP, id))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({"error": "La IP ya está asignada a otro usuario"}), 400

        cursor.execute("UPDATE users SET username = %s, userIP = %s, role = %s WHERE id = %s",
                       (username, userIP, role, id))
        conn.commit()
        return jsonify({"message": "Usuario editado correctamente"}), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/get_users', methods=['GET'])
def get_users():
    #conn = get_db_connection()
    #cursor = conn.cursor()

    try:
        #cursor.execute("SELECT * FROM users")
        users = DatabaseQueries().get_users()
        # users = cursor.fetchall()
         # Estructurar el resultado como una lista de diccionarios
        users_list = []
        for user in users:
            users_list.append({
                "id": user['id'],         # Accediendo por clave en lugar de índice
                "username": user['username'],  # Suponiendo que el campo en tu tabla es 'username'
                "role": user['role'],
                "userIP": user['userIP'],
                "timeStamp": user['created_at']  # Si este es el nombre del campo en la tabla
            })
        return jsonify(users_list), 200
    
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
   # finally:
      #  cursor.close()
       # conn.close()

@app.route('/add_rule', methods=['POST'])
def add_rule():
    data = request.json
    logging.info(data)
    action = data.get('action')
    url = data.get('url')
    type = data.get('type')
    reason = data.get('reason')
    userIPs = data.get('usuarios')
    roles = data.get('roles')
    logging.info("add_rule: action=%s, url=%s, type=%s, reason=%s, usuarios=%s, roles=%s", action, url, type, reason, userIPs, roles)
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

        # Paso 2: Verificar si ya existe una regla con el mismo userIP o role
        if userIPs:
             # Construir la consulta SQL para buscar reglas existentes por userIP
             # genera esto: SELECT id, role FROM users WHERE userIP IN ('192.168.1.10', '192.168.1.12')
            cursor.execute("""
                SELECT id, role, userIP FROM users WHERE userIP IN (%s)
            """ % ','.join(['%s'] * len(userIPs)), tuple(userIPs))
            users = cursor.fetchall()
            logging.info("Usuarios recuperados: %s", users)


            if users:
                for user in users:
                    user_id, role,userIP = user
                    # Verificar si ya existe una regla con el mismo userIP pero con una acción diferente
                    cursor.execute("""
                        SELECT action FROM rules_by_ip
                        WHERE userIP = %s AND blocked_website_id = %s
                    """, (userIP, blocked_website_id))
                    existing_action = cursor.fetchone()
                    logging.info("existing_action: %s", existing_action)
                    if existing_action:
                        if existing_action[0] != action: # si es diferente acción y está añadida la borramos
                            # Si ya existe con una acción diferente, eliminamos esa regla
                            cursor.execute("""
                                DELETE FROM rules_by_ip
                                WHERE userIP = %s AND blocked_website_id = %s
                            """, (userIP, blocked_website_id))
                            logging.info(f"Regla para la IP {userIP} con acción diferente eliminada")
                    # Verificar si ya existe una regla con la misma userIP y acción       
                    cursor.execute("""
                        SELECT 1 FROM rules_by_ip
                        WHERE userIP = %s AND blocked_website_id = %s AND action = %s
                    """, (userIP, blocked_website_id, action))
                    existing_rule = cursor.fetchone()
                    if existing_rule:
                        return jsonify({"message": f"La regla para esta IP {userIP} ya existe con la acción {action}"}), 400

                    cursor.execute("INSERT INTO rules_by_ip (action, userIP, blocked_website_id, user_id) VALUES (%s, %s, %s, %s)", 
                                    (action, userIP, blocked_website_id, user_id))

        # Verificar si ya existe una regla para el rol
        all_roles = ['student', 'teacher', 'public']
        if roles:
            for role in roles:
                # Verificar si ya existe una regla para el mismo rol y sitio web
                cursor.execute("""
                    SELECT action 
                    FROM rules_by_role rbr
                    WHERE rbr.role = %s AND rbr.blocked_website_id = %s
                """, (role, blocked_website_id))
                existing_role_action = cursor.fetchall()
                logging.info("existing_role_action: %s", existing_role_action)
                if existing_role_action:
                    if existing_role_action[0] != action:
                        # Si ya existe una regla con una acción diferente, eliminarla
                        cursor.execute("""
                            DELETE FROM rules_by_role
                            WHERE role = %s AND blocked_website_id = %s
                        """, (role, blocked_website_id))

                # Insertar en rules_by_role
                cursor.execute("INSERT INTO rules_by_role (action, role, blocked_website_id) VALUES (%s, %s, %s)", 
                            (action, role, blocked_website_id))
                            # Insertar los roles faltantes como "autorizar"
            for missing_role in all_roles:
                if missing_role not in roles:
                    cursor.execute("""
                        SELECT 1 
                        FROM rules_by_role rbr
                        WHERE rbr.role = %s AND rbr.blocked_website_id = %s
                    """, (missing_role, blocked_website_id))
                    existing_auth_rule = cursor.fetchone()

                    if not existing_auth_rule:
                        # Insertar el rol faltante como autorizado
                        cursor.execute("INSERT INTO rules_by_role (action, role, blocked_website_id) VALUES (%s, %s, %s)", 
                                    ('autorizar', missing_role, blocked_website_id))

        conn.commit()
        return jsonify({"message": "Regla añadida correctamente"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        try:
            if cursor:
                cursor.fetchall()  # Consumir cualquier resultado pendiente
        except mysql.connector.errors.InterfaceError:
            pass  # No hay más resultados, continuar
        cursor.close()
        conn.close()


@app.route('/edit_rule', methods=['POST'])
def edit_rule():
    data = request.json
    action = data.get('action')
    url = data.get('url')
    type = data.get('type')
    reason = data.get('reason')
    userIPs = data.get('usuarios')
    roles = data.get('roles')

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
        if userIPs is not None:
            if not userIPs:
                cursor.execute("DELETE FROM rules_by_ip WHERE blocked_website_id = %s", (blocked_website_id,))
            # Obtener las IPs actuales de la base de datos
            cursor.execute("SELECT userIP FROM rules_by_ip WHERE blocked_website_id = %s AND action = %s", (blocked_website_id, action))
            current_ips = [row[0] for row in cursor.fetchall()]
            # Eliminar las IPs que están en la base de datos pero no en el nuevo JSON
            for ip in current_ips:
                if ip not in userIPs:
                    cursor.execute("DELETE FROM rules_by_ip WHERE blocked_website_id = %s AND userIP = %s AND action = %s", 
                           (blocked_website_id, ip, action))


            for ip in userIPs:
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
                    # Obtener el user_id correspondiente a la IP
                    cursor.execute("SELECT id FROM users WHERE userIP = %s", (ip,))
                    user = cursor.fetchone()

                    if user:
                        user_id = user[0]  # Obtener el user_id de la consulta

                        # Insertar la nueva entrada en rules_by_ip
                        cursor.execute("""
                            INSERT INTO rules_by_ip (action, userIP, blocked_website_id, user_id)
                            VALUES (%s, %s, %s, %s)
                        """, (action, ip, blocked_website_id, user_id))
                    else:
                        return jsonify({"message": f"No se encontró el usuario con la IP {ip}"}), 400

        # Verificar si el role ha cambiado y actualizar en rules_by_role
        logging.info(f"roles: {roles}")
        if roles is not None:
            logging.info(f"roles: {roles}")
            if not roles:  # Si el array de roles está vacío
                logging.info("Eliminando todos los roles porque el array está vacío")
                # Eliminar todos los roles asociados a este blocked_website_id
                cursor.execute("DELETE FROM rules_by_role WHERE blocked_website_id = %s", (blocked_website_id,))
            else:
                # Obtener los roles actuales de la base de datos
                cursor.execute("SELECT role FROM rules_by_role WHERE blocked_website_id = %s", (blocked_website_id,))
                current_roles = [row[0] for row in cursor.fetchall()]
                #logging.info("current_roles: " ,current_roles)
                
                # Eliminar roles que están en la base de datos pero no en el nuevo JSON
                for role in current_roles:
                    if role not in roles:
                        logging.info(f"Eliminando rol: {role}")
                        cursor.execute("DELETE FROM rules_by_role WHERE blocked_website_id = %s AND role = %s", 
                                    (blocked_website_id, role))

                # Agregar o actualizar roles que están en el nuevo JSON pero no en la base de datos
                for role in roles:
                    if role not in current_roles:
                        logging.info(f"Agregando nuevo rol: {role}")
                        # Insertar el nuevo rol
                        cursor.execute("""
                            INSERT INTO rules_by_role (action, role, blocked_website_id)
                            VALUES (%s, %s, %s)
                        """, (action, role, blocked_website_id))
                    else:
                        # Actualizar el action si el rol ya existe
                        logging.info(f"Actualizando acción para el rol: {role}")
                        cursor.execute("""
                            UPDATE rules_by_role 
                            SET action = %s
                            WHERE blocked_website_id = %s AND role = %s
                        """, (action, blocked_website_id, role))

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


@app.route('/list_rules', methods=['GET'])
def list_rules():
   # conn = get_db_connection()
   # cursor = conn.cursor()

    try:
        # Llamar a las funciones de consulta
        rules = DatabaseQueries().get_all_rules()
        users = DatabaseQueries().get_users_by_ip()
        roles = DatabaseQueries().get_roles_by_rule()

        # Procesar la información y combinar los resultados
        rules_list = []
        seen_blocked_website_ids = set()
        for rule in rules:
            blocked_website_id = rule['blocked_website_id']
            # Si este blocked_website_id ya fue agregado, saltamos esta iteración
            if blocked_website_id in seen_blocked_website_ids:
                continue
            url = rule['URL']
            categoria = rule['Categoria']
            accion = rule['Accion']

            # Marcar el blocked_website_id como visto
            seen_blocked_website_ids.add(blocked_website_id)

            # Buscar los usuarios asociados a esta regla (por blocked_website_id)
            usuarios = [
                {
                    "user_id": user['user_id'],
                    "userIP": user['IP_del_Usuario'],
                    "role": user['Rol_del_Usuario'],
                    "action": user['Accion']
                } for user in users if user['blocked_website_id']== blocked_website_id
            ]


            # Buscar los roles asociados a esta regla (por blocked_website_id)
            roles_assoc = [
                {
                    "role": role['Rol_de_la_Regla'],
                    "role_id": role['rule_role_id'],
                    "action": role['Accion']
                } for role in roles if role['blocked_website_id'] == blocked_website_id
            ]

            # Agregar la regla a la lista
            rules_list.append({
                "blocked_website_id": blocked_website_id,
                "url": url,
                "categoria": categoria,
                "usuarios": usuarios,
                "roles": roles_assoc
            })

        return Response(json.dumps({"rules": rules_list}, indent=4), mimetype='application/json')

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
   # finally:
    #    cursor.close()
    #    conn.close()



''' data = request.json
    action = data.get('action')
    url = data.get('url')
    type = data.get('type')
    reason = data.get('reason')
    userIP = data.get('userIP')
    role = data.get('role')
'''
@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    data = request.json
    logging.info(data)
    url = data.get('url')
    usuarios = data.get('usuarios',[])
    roles = data.get('roles', [])
    logging.info(f"URL: {url}, Usuarios: {usuarios}, Roles: {roles}")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Eliminar reglas por IP para cada usuario
        for usuario in usuarios:
            ip_usuario = usuario.get('userIP')
            logging.info(f"IP del usuario: {ip_usuario}")
            if ip_usuario and ip_usuario != 'ALL':
                cursor.execute("""
                    DELETE FROM rules_by_ip
                    WHERE userIP = %s
                    AND blocked_website_id = (SELECT id FROM blocked_websites WHERE url = %s)
                """, (ip_usuario, url))

        # Eliminar reglas por rol para cada rol
        for rol in roles:
            rol_usuario = rol.get('role')
            if rol_usuario:
                cursor.execute("""
                    DELETE FROM rules_by_role
                    WHERE role = %s
                    AND blocked_website_id = (SELECT id FROM blocked_websites WHERE url = %s)
                """, (rol_usuario, url))

        conn.commit()
        return jsonify({"message": "Regla eliminada correctamente"}), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
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



    """
  # Consulta principal: obtener la información básica de los sitios bloqueados
        query_main = ""
            SELECT
                bw.id AS blocked_website_id,
                bw.url AS URL,
                bw.type AS Categoria,
                rip.action AS Accion
            FROM
                rules_by_ip rip
            JOIN
                blocked_websites bw ON rip.blocked_website_id = bw.id
            UNION
            SELECT
                bw.id AS blocked_website_id,
                bw.url AS URL,
                bw.type AS Categoria,
                rbr.action AS Accion
            FROM
                rules_by_role rbr
            JOIN
                blocked_websites bw ON rbr.blocked_website_id = bw.id
            ORDER BY blocked_website_id ASC;
        ""
        cursor.execute(query_main)
        rules = cursor.fetchall()

        # Consulta para obtener usuarios asociados a las reglas basadas en IP
        query_users = ""
            SELECT
                u.id AS user_id,
                u.userIP AS IP_del_Usuario,
                u.role AS Rol_del_Usuario,
                rip.blocked_website_id,
                rip.action AS Accion
            FROM
                rules_by_ip rip
            LEFT JOIN
                users u ON rip.user_id = u.id
            ORDER BY user_id ASC;
        ""
        cursor.execute(query_users)
        users = cursor.fetchall()

        # Consulta para obtener roles asociados a las reglas
        query_roles = ""
            SELECT
                rbr.id AS rule_role_id,
                rbr.role AS Rol_de_la_Regla,
                rbr.blocked_website_id,
                rbr.action AS Accion
            FROM
                rules_by_role rbr
            ORDER BY rule_role_id ASC;
        ""
        cursor.execute(query_roles)
        roles = cursor.fetchall()
 
# Procesar la información y combinar los resultados
        rules_list = []
        for rule in rules:
            blocked_website_id = rule[0]
            url = rule[1]
            categoria = rule[2]
            accion = rule[3]

            # Buscar los usuarios asociados a esta regla (por blocked_website_id)
            usuarios = [
                {
                    "user_id": user[0], #if user[0] is not None else "ALL",
                    "userIP": user[1], #if user[1] is not None else "ALL",
                    "role": user[2], #if user[2] is not None else "ALL"
                    "action": user[4]
                } for user in users if user[3] == blocked_website_id
            ]
            
           
            # Buscar los roles asociados a esta regla (por blocked_website_id)
            roles_assoc = [
                {
                    "role": role[1],
                    "role_id": role[0],
                    "action": role[3]
                } for role in roles if role[2] == blocked_website_id
            ]



            # Agregar la regla a la lista
            rules_list.append({
                "blocked_website_id": blocked_website_id,
                "url": url,
                "categoria": categoria,                
                "usuarios": usuarios,
                "roles": roles_assoc
            })
    
    """