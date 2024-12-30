import json
import logging
from flask import Blueprint, Response, jsonify, request
import mysql
from db import get_db_connection
from db_queries import DatabaseQueries

filter_bp = Blueprint('filter', __name__)
db_queries = DatabaseQueries()

@filter_bp.route('/add_blocked_site', methods=['POST'])
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
        cursor.execute("SELECT id FROM blocked_websites WHERE url = %s", (url,))
        site = cursor.fetchone()
        if site:
            return jsonify({"message": "Website already blocked"}), 400

        cursor.execute("INSERT INTO blocked_websites (url, type, reason) VALUES (%s, %s, %s)", 
                       (url, category, reason))
        conn.commit()
        return jsonify({"message": f"Added {url} to blocked list."}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()

@filter_bp.route('/add_rule', methods=['POST'])
def add_rule():
    data = request.json
    action = data.get('action')
    url = data.get('url')
    rule_type = ','.join(data.get('type')) if isinstance(data.get('type'), list) else data.get('type')
    reason = data.get('reason')
    user_ips = data.get('usuarios')
    roles = data.get('roles')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Verificar si ya existe una regla en `rules_by_ip` o `rules_by_role` para esta URL
        cursor.execute("SELECT id FROM blocked_websites WHERE url = %s", (url,))
        website = cursor.fetchone()
        
        if website:
            blocked_website_id = website[0]

            # Verificar en `rules_by_ip`
            cursor.execute("SELECT 1 FROM rules_by_ip WHERE blocked_website_id = %s", (blocked_website_id,))
            rule_in_ip = cursor.fetchall()

            # Verificar en `rules_by_role`
            cursor.execute("SELECT 1 FROM rules_by_role WHERE blocked_website_id = %s", (blocked_website_id,))
            rule_in_role = cursor.fetchall()

            if rule_in_ip or rule_in_role:
                # Regla ya existente; cerrar resultados pendientes y retornar mensaje sin error de servidor
                cursor.fetchall()  # Consumir cualquier resultado pendiente
                return jsonify({"message": f"Ya existe una regla para la URL {url}. Usa el endpoint de edición."}), 400

        else:
            # Insertar la URL en `blocked_websites` si no existe
            cursor.execute(
                "INSERT INTO blocked_websites (url, type, reason) VALUES (%s, %s, %s)", 
                (url, rule_type, reason)
            )
            conn.commit()
            blocked_website_id = cursor.lastrowid  # Obtener el ID recién insertado

        # Paso 2: Insertar reglas en `rules_by_ip` si hay IPs especificadas
        if user_ips:
            for user_ip in user_ips:
                # Buscar el ID de usuario correspondiente a la IP
                cursor.execute("SELECT id FROM users WHERE userIP = %s", (user_ip,))
                user = cursor.fetchone()

                if not user:
                    cursor.fetchall()  # Asegurarse de consumir resultados pendientes
                    return jsonify({"error": f"IP {user_ip} no está registrada en la tabla de usuarios."}), 400

                user_id = user[0]
                # Insertar la regla para la IP
                cursor.execute(
                    "INSERT INTO rules_by_ip (action, userIP, blocked_website_id, user_id) VALUES (%s, %s, %s, %s)", 
                    (action, user_ip, blocked_website_id, user_id)
                )
               

        # Paso 3: Insertar reglas en `rules_by_role` si hay roles especificados
        all_roles = ['student', 'teacher', 'public']
        if roles:
            for role in roles:
                cursor.execute(
                    "INSERT INTO rules_by_role (action, role, blocked_website_id) VALUES (%s, %s, %s)", 
                    (action, role, blocked_website_id)
                )
                # Para los roles que no se especificaron, se crean reglas como "autorizar" por defecto
        for missing_role in all_roles:
            if missing_role not in roles:
                cursor.execute("""
                    SELECT 1 
                    FROM rules_by_role rbr
                    WHERE rbr.role = %s AND rbr.blocked_website_id = %s
                """, (missing_role, blocked_website_id))
                existing_rule = cursor.fetchone()
                # Determinar acción basada en la acción especificada para la IP
                if action == 'autorizar':
                    # Si no existe una regla, se crea con la acción "bloquear"
                    if not existing_rule:
                        cursor.execute("INSERT INTO rules_by_role (action, role, blocked_website_id) VALUES (%s, %s, %s)", 
                                    ('bloquear', missing_role, blocked_website_id))
                elif action == 'bloquear':
                    # Si no existe una regla, se crea con la acción "autorizar"
                    if not existing_rule:
                        cursor.execute("INSERT INTO rules_by_role (action, role, blocked_website_id) VALUES (%s, %s, %s)", 
                                    ('autorizar', missing_role, blocked_website_id))

        conn.commit()
        return jsonify({"message": "Regla añadida correctamente"}), 201

    except mysql.connector.Error as err:
        # Manejo de errores de base de datos con un mensaje claro
        return jsonify({"error": f"Error de base de datos: {str(err)}"}), 500

    finally:
        try:
            cursor.fetchall()  # Consumir resultados pendientes antes de cerrar
        except mysql.connector.errors.InterfaceError:
            pass  # No hay más resultados
        cursor.close()
        conn.close()



@filter_bp.route('/edit_rule', methods=['POST'])
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
            #if not userIPs:
                #cursor.execute("DELETE FROM rules_by_ip WHERE blocked_website_id = %s", (blocked_website_id,))
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
            logging.info(f"action: {action}")           
            # Obtener los roles actuales de la base de datos con sus acciones
            cursor.execute("SELECT role, action FROM rules_by_role WHERE blocked_website_id = %s", (blocked_website_id,))
            current_roles = cursor.fetchall()  # Obtener los roles y las acciones actuales
            #current_roles = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Agregar más logs para ver qué está sucediendo
            logging.info(f"Consulta SQL ejecutada para roles con blocked_website_id: {blocked_website_id}")
            logging.info(f"Roles obtenidos de la base de datos: {current_roles}")

            # Separar roles bloqueados y autorizados
            current_blocked_roles = [row[0] for row in current_roles if row[1] == 'bloquear']
            current_authorized_roles = [row[0] for row in current_roles if row[1] == 'autorizar']

            logging.info(f"current_blocked_roles: {current_blocked_roles}")
            logging.info(f"current_authorized_roles: {current_authorized_roles}")
            #logging.info("current_roles: " ,current_roles)
                # Mover roles de 'bloquear' a 'autorizar' si han sido eliminados del JSON
            if action == "bloquear":
                for role in current_blocked_roles:
                    if role not in roles:  # El rol ya no está en el JSON, cambiarlo a 'autorizar'
                        logging.info(f"Moviendo rol {role} de 'bloquear' a 'autorizar'")
                        cursor.execute("UPDATE rules_by_role SET action = 'autorizar' WHERE blocked_website_id = %s AND role = %s",
                                    (blocked_website_id, role))                       

                # Mantener los roles que aún están autorizados pero no deben ser bloqueados
                for role in current_authorized_roles:
                    if role  in roles:  # Si el rol no está en el JSON, mantenerlo en 'bloquear'
                        logging.info(f"Moviendo rol {role} de 'autorizar' a 'bloquear'")
                        cursor.execute("UPDATE rules_by_role SET action = 'bloquear' WHERE blocked_website_id = %s AND role = %s",
                                    (blocked_website_id, role))
            elif action == "autorizar":
                # Mover roles de 'autorizar' a 'bloquear' si están presentes en el JSON
                for role in current_authorized_roles:
                    if role not in roles:  # El rol está en el JSON, cambiarlo a 'bloquear'
                        logging.info(f"Moviendo rol {role} de 'autorizar' a 'bloquear'")
                        cursor.execute("UPDATE rules_by_role SET action = 'bloquear' WHERE blocked_website_id = %s AND role = %s",
                                    (blocked_website_id, role))
                # Mantener los roles que aún están bloqueados pero no deben ser autorizados
                for role in current_blocked_roles:
                    if role  in roles:  # Si el rol no está en el JSON, mantenerlo en 'autorizar'
                        logging.info(f"Moviendo rol {role} de 'bloquear' a 'autorizar'")
                        cursor.execute("UPDATE rules_by_role SET action = 'autorizar' WHERE blocked_website_id = %s AND role = %s",
                                    (blocked_website_id, role))
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


@filter_bp.route('/list_rules', methods=['GET'])
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
@filter_bp.route('/delete_rule', methods=['POST'])
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



@filter_bp.route('/add_keyword', methods=['POST'])
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
@filter_bp.route('/delete_keyword', methods=['POST'])
def delete_keyword():
    data = request.json
    keyword = data.get('keyword')

    if not keyword: 
        return jsonify({"error": "Falta la palabra clave"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM malicious_keywords WHERE keyword = %s", (keyword,))
        conn.commit()    
        return jsonify({"message": "Palabra clave eliminada correctamente"}), 200
    except mysql.connector.Error as err:    
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()
@filter_bp.route('/get_keywords', methods=['GET'])
def keywords():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT keyword FROM malicious_keywords")
        keywords = cursor.fetchall()
        return jsonify(keywords), 200
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()
