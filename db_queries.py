import datetime
from errno import errorcode
import http
import logging

import mysql.connector
from mysql.connector import Error
from db import get_db_connection 


#logging_config.basicConfig(level=logging_config.INFO) 
#logging_config.basicConfig(level=logging_config.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
class DatabaseQueries:
    def __init__(self):
        self.db_connection = None
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

    def get_blocked_site_by_ip(self, client_ip, requested_url):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar si la URL está bloqueada o autorizada para la IP dada
        query = """
        SELECT bw.url, bw.type, bw.reason, rip.action
        FROM rules_by_ip rip
        JOIN blocked_websites bw ON rip.blocked_website_id = bw.id
        WHERE rip.userIP = %s AND bw.url = %s
        """
        cursor.execute(query, (client_ip, requested_url))
        return cursor.fetchone()  # Devuelve una sola fila o None si no se encuentra
    
    def get_authorized_ips_for_url(self, requested_url):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)

        query = """
        SELECT userIP 
        FROM rules_by_ip rip
        JOIN blocked_websites bw ON rip.blocked_website_id = bw.id
        WHERE bw.url = %s AND rip.action = 'autorizar'
        """
        cursor.execute(query, (requested_url,))
        authorized_ips = [row['userIP'] for row in cursor.fetchall()]
        return authorized_ips #devolverá las IPs autorizadas para la URL solicitada
    def get_users(self):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar todos los usuarios
        query = "SELECT * FROM users"
        cursor.execute(query)
        return cursor.fetchall()    
    
    def get_iduser_by_ip(self, userIP):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)
        query = "SELECT id FROM users WHERE userIP = %s"
        cursor.execute(query, (userIP,))
        result = cursor.fetchone()
        cursor.close()
        return result['id'] if result else None

    def get_role_rules(self, role, request_url):
        cursor = self.db_connection.cursor(dictionary=True)

        query = """
        SELECT bw.url, bw.type, bw.reason, rbr.action
        FROM rules_by_role rbr
        JOIN blocked_websites bw ON rbr.blocked_website_id = bw.id
        WHERE rbr.role = %s AND bw.url = %s
        """
        cursor.execute(query, (role, request_url))
        return cursor.fetchone()

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
        #except pymysql.MySQLError as err:
        except mysql.connector.Error as err:
            logging.error(f"Error en la consulta de roles: {err}")
            result = []  # En caso de error devolvemos una lista vacía o lo que sea apropiado
        finally:
            cursor.close()  # Cerramos el cursor para liberar recursos
        return result


    def historical_register(self, user_id, url, action, user_role):
        # Código para guardar en la base de datos        
        self.check_connection()
        cursor = self.db_connection.cursor()
        #cursor = self.db_connection.cursor(dictionary=True)
        try:
           #if user_role:
            query = "INSERT INTO history ( user_id, url, action, user_rol, timestamp ) VALUES (%s, %s, %s, %s, NOW())"
            cursor.execute(query, (user_id, url, action, user_role))            
            #cursor.execute(query, ( user_id, url, action, user_role))
            #else:
                #query = "INSERT INTO historial (ip, url, accion, fecha) VALUES (%s, %s, %s, NOW())"
                #cursor.execute(query, (client_ip, url, action))
            self.db_connection.commit()
            logging.info(f"Historial registrado: user_id={user_id},  role= {user_role}, URL={url}, Accion={action} ")
            return True  # Indica que se guardó correctamente
        #except pymysql.MySQLError as err:
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                logging.error("Acceso denegado a la base de datos")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                logging.error("Base de datos no encontrada")
            else:
                logging.error(err)
        finally:
            cursor.close()

    #funcion para obtener histórico de los últimos 6 meses
    def getHistorical(self, start_date, end_date):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)
        try:
            query2= """SELECT h.id, h.user_id, h.url, h.action, h.user_rol, u.userIP, h.timestamp,
                (SELECT bw.type FROM blocked_websites bw WHERE bw.url = h.url) AS type
            FROM history h
            JOIN users u ON h.user_id = u.id
            WHERE h.timestamp BETWEEN %s AND %s;"""

            cursor.execute(query2, (start_date, end_date))
            result =  cursor.fetchall()
        finally:
            cursor.close()  # Cerramos el cursor para liberar recursos
        return result

    #funcion para filtrar histórico por mes como parámetro
    def getHistoricalForMonth(self, month):
        self.check_connection()
        cursor = self.db_connection.cursor(dictionary=True)
        try:
           # Filtrar por mes específico en la columna `timestamp`
            query = """
                SELECT h.id, h.user_id, h.url, h.action, h.user_rol, u.userIP, h.timestamp,
                       (SELECT bw.type FROM blocked_websites bw WHERE bw.url = h.url) AS type
                FROM history h
                JOIN users u ON h.user_id = u.id
                WHERE MONTH(h.timestamp) = %s
            """
            cursor.execute(query, (month,))
            result =  cursor.fetchall()
        finally:    
            cursor.close()  # Cerramos el cursor para liberar recursos
        return result

    def done(self):
        if self.db_connection.is_connected():
            self.db_connection.close()
            logging.info("Conexión a la base de datos cerrada")
