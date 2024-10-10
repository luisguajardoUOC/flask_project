import http
import logging
from mysql.connector import Error
from db import get_db_connection 

class DatabaseQueries:
    def __init__(self):
        # Conectar a la base de datos
        self.db_connection = get_db_connection()
        if not self.db_connection:
            logging.error("No se pudo conectar a la base de datos.")
    

    def get_blocked_sites(self, client_ip):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar las reglas de bloqueo por IP
        query = """
        SELECT bw.url, bw.type, bw.reason
        FROM rules_by_ip rip
        JOIN blocked_websites bw ON rip.blocked_website_id = bw.id
        WHERE rip.userIP = %s
        """
        cursor.execute(query, (client_ip,))
        return cursor.fetchall()

    def get_role_rules(self, role):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar las reglas de bloqueo por rol
        query = """
        SELECT bw.url, bw.type, bw.reason
        FROM rules_by_role rbr
        JOIN blocked_websites bw ON rbr.blocked_website_id = bw.id
        WHERE rbr.role = %s
        """
        cursor.execute(query, (role,))
        return cursor.fetchall()

    def get_role_user(self, userIP):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar el rol del usuario
        query = "SELECT role FROM users WHERE ip_address = %s"
        cursor.execute(query, (userIP,))
        result = cursor.fetchone()
        if result:
            return result['role']
        else:
            return None  # Devolver None si no se encuentra ningún rol

    def get_authorized_sites(self):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar los sitios autorizados
        query = "SELECT url FROM authorized_websites"
        cursor.execute(query)
        return [row['url'] for row in cursor.fetchall()]
    
    def get_malicious_keywords(self):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar todas las palabras clave maliciosas
        query = "SELECT keyword FROM malicious_keywords"
        cursor.execute(query)
        return [row['keyword'] for row in cursor.fetchall()]

    def done(self):
        if self.db_connection.is_connected():
            self.db_connection.close()
            logging.info("Conexión a la base de datos cerrada")
