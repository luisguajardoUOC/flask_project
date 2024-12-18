import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os

# Cargar variables de entorno
load_dotenv()

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            port=int(os.getenv("DB_PORT")),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
        connection.start_transaction(isolation_level='READ COMMITTED')
        return connection
    except mysql.connector.Error as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None


"""def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            port=3306,
            password="rootpassword",
            database="flask_db"  # Asegúrate de especificar la base de datos
        )
        return connection
    except Error as e:
        print(f"Error al conectar a la base de datos: {e}")
        return None """ 
