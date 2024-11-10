@filter_bp.route('/add_rule', methods=['POST'])
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
    
    # Establecer conexión con la base de datos
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Paso 1: Verificar si la URL ya existe en la tabla `blocked_websites`
        cursor.execute("SELECT id FROM blocked_websites WHERE url = %s", (url,))
        website = cursor.fetchone()

        # Si la URL existe, obtener su `id`; de lo contrario, insertarla en `blocked_websites`
        if website:
            blocked_website_id = website[0]
        else:
            cursor.execute("INSERT INTO blocked_websites (url, type, reason) VALUES (%s, %s, %s)", 
                           (url, ','.join(type), reason))
            conn.commit()
            blocked_website_id = cursor.lastrowid

        # Paso 2: Crear reglas para cada IP del usuario, si se especificaron `userIPs`
        if userIPs:

            # Consulta SQL para verificar si cada IP de usuario ya tiene una regla para la URL solicitada
            cursor.execute("""
                SELECT id, role, userIP FROM users WHERE userIP IN (%s)
            """ % ','.join(['%s'] * len(userIPs)), tuple(userIPs))
            users = cursor.fetchall()
            logging.info("Usuarios recuperados: %s", users)

            # Verificar si ya existe una regla con el mismo `userIP` pero con una acción diferente
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
                            # Si ya existe una acción diferente para la IP y URL, eliminarla
                            cursor.execute("""
                                DELETE FROM rules_by_ip
                                WHERE userIP = %s AND blocked_website_id = %s
                            """, (userIP, blocked_website_id))
                            logging.info(f"Regla para la IP {userIP} con acción diferente eliminada")
                    # Verificar si la misma acción ya existe para evitar duplicados
                    cursor.execute("""
                        SELECT 1 FROM rules_by_ip
                        WHERE userIP = %s AND blocked_website_id = %s AND action = %s
                    """, (userIP, blocked_website_id, action))
                    existing_rule = cursor.fetchone()
                    if existing_rule:
                        return jsonify({"message": f"La regla para esta IP {userIP} ya existe con la acción {action}"}), 400
                    # Insertar la nueva regla para la IP
                    cursor.execute("INSERT INTO rules_by_ip (action, userIP, blocked_website_id, user_id) VALUES (%s, %s, %s, %s)", 
                                    (action, userIP, blocked_website_id, user_id))

        # Paso 3: Crear o actualizar reglas de filtrado para cada rol
        all_roles = ['student', 'teacher', 'public']
        if roles:
            for role in roles:
                # Verificar si ya existe una regla para el mismo rol y URL
                cursor.execute("""
                    SELECT action 
                    FROM rules_by_role rbr
                    WHERE rbr.role = %s AND rbr.blocked_website_id = %s
                """, (role, blocked_website_id))
                existing_role_action = cursor.fetchall()
                logging.info("existing_role_action: %s", existing_role_action)
                # Si ya existe una acción diferente, eliminar la regla para reemplazarla
                if existing_role_action:
                    if existing_role_action[0] != action:
                        # Si ya existe una regla con una acción diferente, eliminarla
                        cursor.execute("""
                            DELETE FROM rules_by_role
                            WHERE role = %s AND blocked_website_id = %s
                        """, (role, blocked_website_id))

                # Insertar la nueva regla para el rol
                cursor.execute("INSERT INTO rules_by_role (action, role, blocked_website_id) VALUES (%s, %s, %s)", 
                            (action, role, blocked_website_id))

            # Para los roles que no se especificaron, se crean reglas como "autorizar" por defecto
            for missing_role in all_roles:
                if missing_role not in roles:
                    cursor.execute("""
                        SELECT 1 
                        FROM rules_by_role rbr
                        WHERE rbr.role = %s AND rbr.blocked_website_id = %s
                    """, (missing_role, blocked_website_id))
                    existing_auth_rule = cursor.fetchone()
                    # Si no existe una regla de autorización, se crea
                    if not existing_auth_rule:
                        # Insertar el rol faltante como autorizado
                        cursor.execute("INSERT INTO rules_by_role (action, role, blocked_website_id) VALUES (%s, %s, %s)", 
                                    ('autorizar', missing_role, blocked_website_id))
        # Guardar todos los cambios en la base de datos
        conn.commit()
        return jsonify({"message": "Regla añadida correctamente"}), 201
    # Manejo de errores en caso de fallos de conexión o ejecución SQL
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    # Liberar recursos cerrando el cursor y la conexión
    finally:
        try:
            if cursor:
                cursor.fetchall()  # Consumir cualquier resultado pendiente
        except mysql.connector.errors.InterfaceError:
            pass  # No hay más resultados, continuar
        cursor.close()
        conn.close()
