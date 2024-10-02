
"""
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
"""

import subprocess
import os
import signal
import json
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.json
    username = data.get('username')
    userIP = data.get('userIP')
    role = data.get('role')

    if not username or not userIP or not role:
        return jsonify({"error": "Faltan datos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
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
