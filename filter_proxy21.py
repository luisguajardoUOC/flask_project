import mysql.connector
from mysql.connector import Error

class Filter:
    def __init__(self):
        # Conectar a la base de datos
        self.db_connection = self.connect_to_db()
        self.blocked_sites = []  # Ya no cargamos desde JSON, lo haremos desde la base de datos
        self.authorized_sites = []
    
    def connect_to_db(self):
        try:
            connection = mysql.connector.connect(
                host='localhost',  # Cambiar por el host de tu base de datos
                database='tu_base_de_datos',  # Nombre de tu base de datos
                user='tu_usuario',  # Usuario de MySQL
                password='tu_contraseña'  # Contraseña de MySQL
            )
            if connection.is_connected():
                print("Conexión a la base de datos MySQL establecida")
                return connection
        except Error as e:
            print(f"Error al conectar a la base de datos: {e}")
            return None

    def get_blocked_sites(self, client_ip):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar las reglas de bloqueo por IP
        query = """
        SELECT bw.url, bw.category, bw.reason
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
        SELECT bw.url, bw.category, bw.reason
        FROM rules_by_role rbr
        JOIN blocked_websites bw ON rbr.blocked_website_id = bw.id
        WHERE rbr.role = %s
        """
        cursor.execute(query, (role,))
        return cursor.fetchall()

    def get_authorized_sites(self):
        cursor = self.db_connection.cursor(dictionary=True)

        # Consultar los sitios autorizados
        query = "SELECT url FROM authorized_websites"
        cursor.execute(query)
        return [row['url'] for row in cursor.fetchall()]

    def request(self, flow: http.HTTPFlow) -> None:
        client_ip = flow.client_conn.address[0]  # Obtener la IP del cliente
        user_role = "student"  # Aquí se obtendría el rol del usuario de alguna manera (quizás desde la base de datos)
        
        # Obtener las reglas basadas en IP desde la base de datos
        blocked_sites_by_ip = self.get_blocked_sites(client_ip)

        # Obtener las reglas basadas en el rol desde la base de datos
        blocked_sites_by_role = self.get_role_rules(user_role)

        # Combinar los sitios bloqueados de IP y rol
        all_blocked_sites = blocked_sites_by_ip + blocked_sites_by_role

        for site in all_blocked_sites:
            if site["url"] in flow.request.pretty_url:
                logging.info(f"Blocking request from {client_ip} for {site['url']}: {flow.request.pretty_url}")
                flow.response = http.Response.make(
                    403,  # Código HTTP 403
                    b"Access to this site is blocked by the proxy.",
                    {"Content-Type": "text/html"}
                )
                flow.metadata["blocked"] = True  # Marcar la solicitud como bloqueada
                return

        # Si no está bloqueado, se deja pasar la solicitud

    def response(self, flow: http.HTTPFlow) -> None:
        # Si la solicitud fue marcada como bloqueada, no continuar
        if flow.metadata.get("blocked", False):
            logging.info(f"Skipping response for blocked request: {flow.request.pretty_url}")
            return  # Detener si la solicitud fue bloqueada en request

        # Si no existe una respuesta (puede haber sido bloqueada), salir
        if flow.response is None:
            return

        # Verificar si la URL está en la lista de sitios autorizados
        if any(site in flow.request.pretty_url for site in self.get_authorized_sites()):
            logging.info(f"Skipping response content analysis for authorized site: {flow.request.pretty_url}")
            return

        # Detectar palabras clave maliciosas en el contenido de la respuesta
        content = flow.response.get_text(strict=False)
        for keyword in explicit_keywords:
            if keyword in content:
                logging.info(f"Suspicious keyword '{keyword}' detected in response content: {flow.request.pretty_url}")

                # Generar respuesta HTTP 403 cuando coincida con el filtro
                flow.response = http.Response.make(
                    403,  # Código de respuesta HTTP 403: Prohibido
                    b"Malicious content detected.",
                    {"Content-Type": "text/html"}
                )
                break  # Detener después de detectar la primera palabra clave


    def done(self):
        if self.db_connection.is_connected():
            self.db_connection.close()
            logging.info("Conexión a la base de datos cerrada")
