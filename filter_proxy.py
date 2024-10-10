import http
import logging
from db_queries import DatabaseQueries
from mitmproxy import ctx,http
logging.basicConfig(level=logging.INFO) 
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class ProxyFilter:
    def __init__(self):
        self.db_queries = DatabaseQueries()
        logging.info("Script filter_proxy.py loaded")
        print("Script filter_proxy.py loaded")

    def request(self, flow: http.HTTPFlow) -> None:
        logging.info("hola")
        ctx.log.info("holaMITMPROXY")
        print(f"Request intercepted: {flow.request.url}")
        #client_ip = flow.client_conn.address[0]  # Obtener la IP del cliente
        client_ip = "192.168.1.10"
        requested_url = flow.request.pretty_url  # Obtener la URL solicitada
        # Registrar en el log la IP del cliente y la URL solicitada
        logging.info(f"Received request from {client_ip} for {requested_url}")        
        # user_role = "student"  # Aquí se obtendría el rol del usuario de alguna manera (quizás desde la base de datos)
        user_role = self.db_queries.get_role_user(client_ip)
        logging.info(f"User role: {user_role}")

        # Obtener las reglas basadas en IP desde la base de datos
        blocked_sites_by_ip = self.db_queries.get_blocked_sites(client_ip)
        logging.info(f"Blocked sites by IP: {blocked_sites_by_ip}")

        # Si hay un rol asociado, obtener las reglas basadas en el rol
        blocked_sites_by_role = []
        if user_role:
            blocked_sites_by_role = self.db_queries.get_role_rules(user_role)

        # Combinar los sitios bloqueados de IP y rol
        all_blocked_sites = blocked_sites_by_ip + blocked_sites_by_role
        logging.info(f"All blocked sites: {all_blocked_sites}")
        #all_blocked_sites = []
        #all_blocked_sites = [{"url": "http://www.edu4java.com/"},{"url": "edu4java.com"}]
        if not all_blocked_sites:
            logging.info(f"No blocked sites for IP {client_ip} and role {user_role}")
        else:
            for site in all_blocked_sites:
                # logging.info(f"Checking blocked site: {site['url']}")
                logging.info(f"flow.request: {flow.request.pretty_url}")
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
        if any(site in flow.request.pretty_url for site in self.db_queries.get_authorized_sites()):
            logging.info(f"Skipping response content analysis for authorized site: {flow.request.pretty_url}")
            return
        # Obtener las palabras maliciosas desde la base de datos
        malicious_keywords = self.db_queries.get_malicious_keywords()
        # Detectar palabras clave maliciosas en el contenido de la respuesta
        content = flow.response.get_text(strict=False)
        for keyword in malicious_keywords:
            if keyword in content:
                logging.info(f"Suspicious keyword '{keyword}' detected in response content: {flow.request.pretty_url}")

                # Generar respuesta HTTP 403 cuando coincida con el filtro
                flow.response = http.Response.make(
                    403,  # Código de respuesta HTTP 403: Prohibido
                    b"Malicious content detected.",
                    {"Content-Type": "text/html"}
                )
                break  # Detener después de detectar la primera palabra clave

addons = [
    ProxyFilter()
]