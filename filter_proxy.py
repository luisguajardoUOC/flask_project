import http
import logging
from db_queries import DatabaseQueries
from mitmproxy import ctx,http
from urllib.parse import urlparse
#logging.basicConfig(level=logging.INFO) 
#logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

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
        client_ip = "192.168.68.104"
        requested_url = flow.request.pretty_url  # Obtener la URL solicitada        
          # Parsear la URL solicitada
        parsed_url = urlparse(requested_url)
        requested_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"  # Domínio con esquema
        logging.info(f"Requested domain: {requested_domain}")
        #requested_domain = flow.request.host  # Obtener el dominio de la URL
        # Registrar en el log la IP del cliente y la URL solicitada
        logging.info(f"Received request from {client_ip} for {requested_url} ({requested_domain})")   
        
        # user_role = "student"  # Aquí se obtendría el rol del usuario de alguna manera (quizás desde la base de datos)
        user_role = self.db_queries.get_role_user(client_ip)
        logging.info(f"User role: {user_role}")

        # Obtener las reglas basadas en IP desde la base de datos
        blocked_sites_by_ip = self.db_queries.get_blocked_site_by_ip(client_ip,requested_domain)
        logging.info(f"Blocked sites by IP: {blocked_sites_by_ip}")

        if blocked_sites_by_ip:
            if blocked_sites_by_ip['action'] == 'autorizar':
                logging.info(f"Skipping block for authorized URL: {requested_domain} by IP")
                self.db_queries.registrar_historico(client_ip, requested_url, 'autorizar')
                return  # No bloqueamos si la URL está autorizada
            #bloqueo si la IP está bloqueada y salimos de la función
            elif blocked_sites_by_ip['action'] == 'bloquear':
                logging.info(f"Blocking request from {client_ip} for {requested_domain}")
                flow.response = http.Response.make(
                    403,  # Código HTTP 403
                    b"Access to this site is blocked by the proxy.",
                    {"Content-Type": "text/html"}
                )
                self.db_queries.registrar_historico( requested_url, 'bloquear', client_ip)
                flow.metadata["blocked"] = True
                return
        # si no hay IP bloqueada revisamos roles bloqueados
        if user_role:
            blocked_sites_by_role = self.db_queries.get_role_rules(user_role,requested_domain)
            logging.info(f"Blocked sites by role: {blocked_sites_by_role}")
            if blocked_sites_by_role:
                if blocked_sites_by_role['action'] == 'autorizar':
                    logging.info(f"Skipping block for authorized URL: {requested_domain} by role")
                    self.db_queries.registrar_historico( requested_url, 'autorizar', user_role)
                    return  # No bloqueamos si la URL está autorizada
                elif blocked_sites_by_role['action'] == 'bloquear':
                    self.db_queries.registrar_historico( requested_url, 'bloquear', user_role)
                    logging.info(f"Blocking request from {client_ip} for {requested_domain}")
                    flow.response = http.Response.make(
                        403,  # Código HTTP 403
                        b"Access to this site is blocked by the proxy.",
                        {"Content-Type": "text/html"}
                    )
                    flow.metadata["blocked"] = True
                    return





        """
        autorized_sites_by_ip = self.db_queries.get_ip_autorized_sites(client_ip)
        logging.info(f"Autorized sites by IP: {autorized_sites_by_ip}")

        # Si hay un rol asociado, obtener las reglas basadas en el rol
        blocked_sites_by_role = []
        if user_role:
            blocked_sites_by_role = self.db_queries.get_role_rules(user_role)
        logging.info(f"Blocked sites by role: {blocked_sites_by_role}")
        # Combinar los sitios bloqueados de IP y rol
        all_blocked_sites = blocked_sites_by_ip + blocked_sites_by_role
        logging.info(f"All blocked sites: {all_blocked_sites}")
        #all_blocked_sites = []
        #all_blocked_sites = [{"url": "http://www.edu4java.com/"},{"url": "edu4java.com"}]
        if not all_blocked_sites:
            logging.info(f"No blocked sites for IP {client_ip} and role {user_role}")
        else:
             # Revisar si la URL solicitada es parte de un sitio autorizado
            is_authorized = any(auth_site["url"] in flow.request.pretty_url for auth_site in autorized_sites_by_ip)

            if is_authorized:
                logging.info(f"Skipping block for authorized URL: {flow.request.pretty_url}")
                return  # No bloqueamos si la URL está autorizada
            for site in all_blocked_sites:
                # logging.info(f"Checking blocked site: {site['url']}")
                logging.info(f"flow.request: {flow.request.pretty_url}")
                  # Si la URL está en los sitios autorizados, no se bloquea                
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
    """
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