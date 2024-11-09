from flask import Blueprint, jsonify, request
import mysql
from db import get_db_connection
from db_queries import DatabaseQueries

auth_bp = Blueprint('auth', __name__)
db_queries = DatabaseQueries()

@auth_bp.route('/add_user', methods=['POST'])
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
        cursor.execute("SELECT id FROM users WHERE userIP = %s", (userIP,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({"error": "La IP ya está asignada a otro usuario"}), 400

        cursor.execute("INSERT INTO users (username, userIP, role) VALUES (%s, %s, %s)", 
                       (username, userIP, role))
        conn.commit()
        return jsonify({"message": "Usuario añadido correctamente"}), 201
    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()

@auth_bp.route('/edit_user', methods=['POST'])
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

@auth_bp.route('/get_users', methods=['GET'])
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

@auth_bp.route('/delete_user/<int:id>', methods=['DELETE'])
def delete_user(id):
    
    if not id:  
        return jsonify({"error": "Faltan datos"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM users WHERE id = %s", (id,))
        conn.commit()    
        return jsonify({"message": "Usuario eliminado correctamente"}), 200
    except mysql.connector.Error as err:    
        return jsonify({"error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()