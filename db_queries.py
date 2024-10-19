import http
import logging
from mysql.connector import Error
from db import get_db_connection 

#logging_config.basicConfig(level=logging_config.INFO) 
#logging_config.basicConfig(level=logging_config.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
class DatabaseQueries:
    def __init__(self):
        # Conectar a la base de datos
        self.db_connection = get_db_connection()
        if not self.db_connection:
            logging.error("No se pudo conectar a la base de datos.")
        else:
            logging.info("Conexión a la base de datos establecida.")
    def check_connection(self):
        # Verificar si la conexión está activa, si no, reconectar
        if not self.db_connection.is_connected():
            self.db_connection = get_db_connection()

    def get_blocked_sites(self, client_ip):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar las reglas de bloqueo por IP
        query = """
        SELECT bw.url, bw.type, bw.reason
        FROM rules_by_ip rip
        JOIN blocked_websites bw ON rip.blocked_website_id = bw.id and rip.action = 'bloquear'
        WHERE rip.userIP = %s
        """
        cursor.execute(query, (client_ip,))
        return cursor.fetchall()
    def get_users(self):
            self.check_connection()
            cursor = self.db_connection.cursor(dictionary=True)

            # Consultar todos los usuarios
            query = "SELECT * FROM users"
            cursor.execute(query)
            return cursor.fetchall()    


    def get_role_rules(self, role):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar las reglas de bloqueo por rol
        query = """
        SELECT bw.url, bw.type, bw.reason
        FROM rules_by_role rbr
        JOIN blocked_websites bw ON rbr.blocked_website_id = bw.id and rbr.action = 'bloquear'
        WHERE rbr.role = %s
        """
        cursor.execute(query, (role,))
        return cursor.fetchall()

    def get_role_user(self, userIP):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar el rol del usuario
        query = "SELECT role FROM users WHERE userIP = %s"
        cursor.execute(query, (userIP,))
        result = cursor.fetchone()
        if result:
            return result['role']
        else:
            return None  # Devolver None si no se encuentra ningún rol
    def get_ip_autorized_sites(self,client_ip):
        cursor = self.db_connection.cursor(dictionary=True)
        # Consultar los sitios autorizados para la IP específica
        query = """
            SELECT bw.url 
            FROM rules_by_ip rip
            JOIN blocked_websites bw ON rip.blocked_website_id = bw.id
            WHERE rip.userIP = %s AND rip.action = 'autorizar'
            """
        cursor.execute(query, (client_ip,))
        result = cursor.fetchall()
        return result
        

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


    def get_all_rules(self):
        logging.info("Ejecutando consulta para obtener todas las reglas.")
        self.check_connection()        
        cursor = self.db_connection.cursor(dictionary=True)        
        try:
            query = """
                SELECT SQL_NO_CACHE
                    bw.id AS blocked_website_id,
                    bw.url AS URL,
                    bw.type AS Categoria,
                    rip.action AS Accion
                FROM
                    rules_by_ip rip
                JOIN
                    blocked_websites bw ON rip.blocked_website_id = bw.id
                UNION
                SELECT SQL_NO_CACHE
                    bw.id AS blocked_website_id,
                    bw.url AS URL,
                    bw.type AS Categoria,
                    rbr.action AS Accion
                FROM
                    rules_by_role rbr
                JOIN
                    blocked_websites bw ON rbr.blocked_website_id = bw.id
                ORDER BY blocked_website_id ASC;
            """
            logging.debug(f"Consulta SQL: {query}")
            cursor.execute(query)
            result =  cursor.fetchall()
            logging.info(f"Resultados obtenidos: {len(result)} reglas")
        finally:
            cursor.close()  # Cerramos el cursor para liberar recursos            
            logging.info("Conexión cerrada correctamente.")
        return result

    def get_users_by_ip(self):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)
        try:
            query = """
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
            """
            cursor.execute(query)
            result =  cursor.fetchall()
        finally:
            cursor.close()  # Cerramos el cursor para liberar recursos
        return result

    def get_roles_by_rule(self):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)
        try:
            query = """
                SELECT
                    rbr.id AS rule_role_id,
                    rbr.role AS Rol_de_la_Regla,
                    rbr.blocked_website_id,
                    rbr.action AS Accion
                FROM
                    rules_by_role rbr
                ORDER BY rule_role_id ASC;
            """
            cursor.execute(query)
            result =  cursor.fetchall()
        finally:
            cursor.close()  # Cerramos el cursor para liberar recursos
        return result

    def done(self):
        if self.db_connection.is_connected():
            self.db_connection.close()
            logging.info("Conexión a la base de datos cerrada")
