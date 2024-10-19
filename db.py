import mysql.connector
from mysql.connector import Error

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="rootpassword",
            database="flask_db"  # Asegúrate de especificar la base de datos
        )
        return connection
    except Error as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None
