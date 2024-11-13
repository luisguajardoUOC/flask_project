import http
import logging
import asyncio
import time
import threading
from db_queries import DatabaseQueries
from mitmproxy import ctx,http, websocket
from urllib.parse import urlparse
#from json_utils import read_block_messages, write_block_messages, load_html_template, load_ips, load_certificates, is_first_connection, register_client_ip
from json_utils import json_utils
from datetime import datetime
#logging.basicConfig(level=logging.INFO) 
#logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class ProxyFilter:
    def __init__(self, inactivity_threshold=60, cleanup_interval=40):
        self.db_queries = DatabaseQueries()
        self.json_utils = json_utils()
        logging.info("Script filter_proxy.py loaded")
        print("Script filter_proxy.py loaded")
        self.connections = {}
        self.authorized_urls_by_ip = {}
        self.inactivity_threshold = inactivity_threshold
        self.cleanup_interval = cleanup_interval
        self.start_cleanup_timer()

    def request(self, flow: http.HTTPFlow) -> None:
        logging.info("Request intercepted")
        print(f"Request intercepted: {flow.request.url}")
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        client_ip = flow.client_conn.address[0]
        client_port = flow.client_conn.address[1]
        user_id = self.db_queries.get_iduser_by_ip(client_ip)
        logging.info(f"Client IP: {client_ip}, Client Port: {client_port}, User ID: {user_id}")

        ips_with_cert = self.json_utils.load_ips()
        if self.json_utils.is_first_connection(client_ip, ips_with_cert):
            self.json_utils.register_client_ip(client_ip)
            logging.info(f"Registered client IP First Connection: {client_ip}")
            certificate = self.json_utils.load_certificates()
            flow.response = http.Response.make(
                200,
                certificate,
                {"Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem",
                 "Content-Type": "application/x-x509-ca-cert"}
            )

        requested_url = flow.request.pretty_url
        parsed_url = urlparse(requested_url)
        requested_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        logging.info(f"Requested domain: {requested_domain}")

        user_role = self.db_queries.get_role_user(client_ip)
        blocked_sites_by_ip = self.db_queries.get_blocked_site_by_ip(client_ip, requested_domain)
        block_message_data = self.json_utils.read_block_messages()

        client_id = id(client_ip)
        connection_id = f"{client_id}-{client_port}-{requested_domain}"
        
        logging.info(f"Initial Request connections: {self.connections}")
        if connection_id not in self.connections:
            connection_data = self.create_connection(connection_id, client_ip, requested_domain)
            logging.info(f"Creating new connection for client {client_ip}, ID {connection_id}")

        connection_data = self.connections[connection_id]
        connection_data["last_activity"] = datetime.now()

        if blocked_sites_by_ip:
            if blocked_sites_by_ip['action'] == 'autorizar':
                if requested_domain not in connection_data["authorized_urls"]:
                    self.db_queries.historical_register(user_id, requested_domain, 'autorizar', user_role)
                    connection_data["authorized_urls"].add(requested_domain)
                    logging.info(f"URL {requested_domain} registered as authorized for IP {client_ip}")
                else:
                    logging.info(f"URL {requested_url} already registered; avoiding duplication.")
                return
            elif blocked_sites_by_ip['action'] == 'bloquear':
                html_content = self.json_utils.load_html_template(block_message_data.get('message_rule'), current_time, requested_domain, client_ip)
                flow.response = http.Response.make(
                    403,
                    html_content.encode(),
                    {"Content-Type": "text/html"}
                )
                if requested_domain not in connection_data["blocked_urls"]:
                    self.db_queries.historical_register(user_id, requested_domain, 'bloquear', user_role)
                    connection_data["blocked_urls"].add(requested_domain)
                    logging.info(f"URL {requested_domain} registered as blocked for IP {client_ip}")
                else:
                    logging.info(f"URL {requested_url} already registered; avoiding duplication.")
                flow.metadata["blocked"] = True
                return

        if user_role:
            blocked_sites_by_role = self.db_queries.get_role_rules(user_role, requested_domain)
            if blocked_sites_by_role:
                if blocked_sites_by_role['action'] == 'autorizar':
                    if requested_domain not in connection_data["authorized_urls"]:
                        self.db_queries.historical_register(user_id, requested_domain, 'autorizar', user_role)
                        connection_data["authorized_urls"].add(requested_domain)
                    return
                elif blocked_sites_by_role['action'] == 'bloquear':
                    html_content = self.json_utils.load_html_template(block_message_data.get('message_rule'), current_time, requested_domain, client_ip)
                    flow.response = http.Response.make(
                        403,
                        html_content.encode(),
                        {"Content-Type": "text/html"}
                    )
                    if requested_domain not in connection_data["blocked_urls"]:
                        self.db_queries.historical_register(user_id, requested_domain, 'bloquear', user_role)
                        connection_data["blocked_urls"].add(requested_domain)
                        logging.info(f"Blocking request from {client_ip} for {requested_domain}")
                    flow.metadata["blocked"] = True
                    return

    def response(self, flow: http.HTTPFlow) -> None:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        client_ip = flow.client_conn.address[0]
        client_port = flow.client_conn.address[1]
        user_id = self.db_queries.get_iduser_by_ip(client_ip)
        user_role = self.db_queries.get_role_user(client_ip)
        requested_url = flow.request.pretty_url
        parsed_url = urlparse(requested_url)
        requested_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

        if flow.metadata.get("blocked", False):
            logging.info(f"Skipping response for blocked request: {flow.request.pretty_url}")
            return

        if flow.response is None:
            return

        if any(site in flow.request.pretty_url for site in self.db_queries.get_authorized_sites()):
            logging.info(f"Skipping response content analysis for authorized site: {flow.request.pretty_url}")
            return

        malicious_keywords = self.db_queries.get_malicious_keywords()
        client_id = id(client_ip)
        connection_id = f"{client_id}-{client_port}-{requested_domain}"
        logging.info(f"Finally RESPONSE  connections: {self.connections}")
        if connection_id not in self.connections:
            connection_data = self.create_connection(connection_id, client_ip, requested_domain)
        else:
            connection_data = self.connections[connection_id]

        content = flow.response.get_text(strict=False)
        for keyword in malicious_keywords:
            block_message_data = self.json_utils.read_block_messages()
            if keyword in content:
                html_content = self.json_utils.load_html_template(block_message_data.get('message_word'), current_time, requested_domain, client_ip)
                flow.response = http.Response.make(
                    403,
                    html_content.encode(),
                    {"Content-Type": "text/html"}
                )
                if requested_domain not in connection_data["blocked_urls"]:
                    self.db_queries.historical_register(user_id, requested_domain, 'bloquear', user_role)
                    connection_data["blocked_urls"].add(requested_domain)
                    logging.info(f"Blocking response from {client_ip} for {requested_domain}")
                else:
                    logging.info(f"URL {requested_url} already registered; avoiding duplication.")               
                break

    def create_connection(self, connection_id, client_ip, url):
        connection_time = datetime.now()
        self.connections[connection_id] = {
            "client_ip": client_ip,
            "start_time": connection_time,
            "last_activity": connection_time,
            "authorized_urls": set(),
            "blocked_urls": set(),
        }
        return self.connections[connection_id]


    """def client_connected(self, client):
        # Registra el inicio de una conexión del cliente
        #client_ip = client.peername[0]
        client_ip= '192.168.68.103'
        logging.info(f"Conexión del cliente iniciada desde client_ip: {client_ip}")
        connection_time = datetime.now()
        # Comprueba si la IP del cliente ya está registrada
        #if client_ip in [conn_data["client_ip"] for conn_data in self.connections.values()]:
        #    logging.info(f"Conexión existente encontrada para IP {client_ip}. No se crea otra.")
        #    return  # Evita crear múltiples conexiones para la misma IP
        # Almacena los detalles de la conexión usando id(client) como clave
        self.connections[id(client)] = {
            "client_ip": client_ip,
            "start_time": connection_time,
            "last_activity": connection_time,  # Inicializa igual a start_time
            "authorized_urls": set(),
        }
        #logging.info(f"***=> connections:{id(client)} - {self.connections}")
        #logging.info(f"Conexión del cliente iniciada desde {client_ip} a las {connection_time}")"""


    # Lógica para limpiar el estado cuando el usuario cierra la pestaña
    def client_disconnected(self, flow: http.HTTPFlow): 
        client_ip = None  # Definir client_ip inicialmente como None       
        # Obtener la IP del cliente desde el objeto flow
        # Verifica que flow tenga el atributo client_conn antes de acceder a él
        if hasattr(flow, 'client_conn') and flow.client_conn:
            client_ip = flow.client_conn.address[0]
            logging.info(f"¿?¿?¿?¿?¿? Conexión del cliente terminada {client_ip}")

        # Limpiar las URLs autorizadas para esta IP si existen en el diccionario
        if client_ip and client_ip in self.authorized_urls_by_ip:
            del self.authorized_urls_by_ip[client_ip]
            logging.info(f"URLs autorizadas borradas para IP {client_ip}")


    def server_disconnected(self, client):
        logging.info(f" ¿?¿?¿?¿?¿? Conexión del SERVIDOR  terminada ")
        layer_id = id(client)
        # Detectar cuando el servidor cierra la conexión (paquete FIN/RST)
        if layer_id in self.connections:
            client_ip, requested_url = self.connections[layer_id]
            logging.info(f"Desconexión detectada (FIN/RST) desde el servidor para el cliente {client_ip} en {requested_url}")
            # Registrar o manejar la desconexión del lado del servidor
            del self.connections[layer_id]  # Limpieza de la conexión



    def record_activity(self, client_conn, url):
        logging.info(f" ===RR===> Registro de actividad para {id(client_conn)}")
        logging.info(f" ===RR===>Conexiones actuales: {self.connections.keys()}")  # Muestra las claves actuales

        client_id = id(client_conn)  # Obtener el ID para buscar en conexiones

        if client_id in self.connections:
            current_time = datetime.now()
            # Actualiza o agrega la URL con su `last_activity`
            self.connections[client_id]["authorized_urls"][url] = current_time
            logging.info(f"Actividad registrada para {url} en cliente {client_id} con tiempo {current_time}")
        else:
            logging.info(f"No se encontró una conexión activa para el cliente con ID {client_id}")


    def start_cleanup_timer(self):
        #Inicia el temporizador que ejecuta la limpieza periódica.
        threading.Timer(self.cleanup_interval, lambda: self.cleanup_inactive_connections(time.time())).start()



    def cleanup_inactive_connections(self, current_time):
        current_time = datetime.fromtimestamp(current_time)  # Convierte el tiempo actual a datetime
        logging.info(f" ******Limpiando conexiones inactivas...{self.connections.items()}")
        #webs que llevan mas tiempo sin actividad
        # Verificar conexiones que han excedido el umbral de inactividad
        inactive_ips = []
        for client_id, connection_data in self.connections.items():
            # Calcular el tiempo de inactividad
            time_inactive = (current_time - connection_data["last_activity"]).total_seconds()
            logging.info(f"Conexión {client_id}: tiempo de inactividad = {time_inactive} segundos")

            # Comprobar si excede el umbral de inactividad
            if time_inactive > self.inactivity_threshold:
                inactive_ips.append(client_id)

        logging.info(f" ******Conexiones inactivas: {inactive_ips}")
        for ip in inactive_ips:
            del self.connections[ip]
            #del self.authorized_urls_by_ip[ip]  # Limpia URLs autorizadas para la IP
            logging.info(f"Conexión de {ip} eliminada por inactividad.")
         # Reinicia el temporizador para continuar la limpieza periódica
        self.start_cleanup_timer()

addons = [
    ProxyFilter()
]


"""
def client_disconnected(self, layer):
        client_ip = layer.metadata.get('client_ip')        
        logging.info(f"DESCONEXION !!!! Conexión del cliente terminada {client_ip}")
        try:
            # Verifica si `is_authorized` está en `metadata` del flujo
            if layer.metadata.get('is_authorized'):
                # Recupera la información de `metadata` para una página autorizada
                user_id = layer.metadata.get('user_id')
                url = layer.metadata.get('url')
                action = 'autorizar'
                user_role = layer.metadata.get('user_role')

                # Registrar en la base de datos para una página autorizada
                self.db_queries.historical_register(user_id, url, action, user_role)
                logging.info(f"Guardado en la base de datos: user_id={user_id}, URL={url}, role={user_role}, acción={action}")
            else:
                logging.info("Desconexión detectada sin autorización en `metadata` para registrar.")
    
        except AttributeError:
            # Manejo del error si `metadata` no está presente en `layer`
            logging.warning("Desconexión detectada: `layer` no contiene `metadata`. No se puede guardar en la base de datos.")

# Si hay IPs autorizadas pero la actual no está en la lista de autorizadas
        # Si no hay reglas específicas para la IP, se verifica si la IP está en las reglas de `rules_by_ip`
        authorized_ips = self.db_queries.get_authorized_ips_for_url(requested_domain)  # Obtener IPs autorizadas de la DB para esta URL
        logging.info(f"Authorized IPs from rules_by_ip: {authorized_ips} for {requested_domain}")
        
        # Si hay IPs autorizadas pero la actual no está en la lista de autorizadas, se bloquea la solicitud
        if authorized_ips and client_ip not in authorized_ips:
            logging.info(f"Blocking request from {client_ip} as it is not authorized for {requested_domain}")
            html_content = self.json_utils.load_html_template(block_message_data.get('message_rule'), current_time, requested_domain, client_ip)
            flow.response = http.Response.make(
                403,  # Código HTTP 403
                html_content.encode(),  # HTML personalizado
                {"Content-Type": "text/html"}
            )
            self.db_queries.registrar_historico(requested_url, 'bloquear', client_ip)
            flow.metadata["blocked"] = True
            return"""    
        # si no hay IP




"""# Si hay IPs autorizadas pero la actual no está en la lista de autorizadas
        # Si no hay reglas específicas para la IP, se verifica si la IP está en las reglas de `rules_by_ip`
        authorized_ips = self.db_queries.get_authorized_ips_for_url(requested_domain)  # Obtener IPs autorizadas de la DB para esta URL
        logging.info(f"Authorized IPs from rules_by_ip: {authorized_ips} for {requested_domain}")
        
        # Si hay IPs autorizadas pero la actual no está en la lista de autorizadas, se bloquea la solicitud
        if authorized_ips and client_ip not in authorized_ips:
            logging.info(f"Blocking request from {client_ip} as it is not authorized for {requested_domain}")
            html_content = self.json_utils.load_html_template(block_message_data.get('message_rule'), current_time, requested_domain, client_ip)
            flow.response = http.Response.make(
                403,  # Código HTTP 403
                html_content.encode(),  # HTML personalizado
                {"Content-Type": "text/html"}
            )
            self.db_queries.registrar_historico(requested_url, 'bloquear', client_ip)
            flow.metadata["blocked"] = True
            return
            
            def websocket_handshake(self, flow:http.HTTPFlow ):
        # Detecta y registra el inicio de una conexión WebSocket
        client_ip = flow.client_conn.address[0]
        logging.info(f"Handshake WebSocket iniciado desde: {client_ip} para {flow.request.host}")

    def websocket_message(self, flow: http.HTTPFlow):
        if flow.websocket is not None:
            last_message = flow.websocket.messages[-1]  # Obtener el último mensaje
            client_ip = flow.client_conn.address[0]
            if last_message.from_client:
                logging.info(f"Mensaje WebSocket enviado por el cliente {client_ip}: {last_message.content}")
            else:
                logging.info(f"Mensaje WebSocket recibido desde el servidor para el cliente {client_ip}: {last_message.content}")
        
            
    def websocket_end(self, flow: http.HTTPFlow):
        client_ip = flow.client_conn.address[0]
        user_id = self.db_queries.get_iduser_by_ip(client_ip)
        requested_url = flow.request.pretty_url
        logging.info(f"Conexión WebSocket finalizada desde: {client_ip} para {requested_url}")

        # Agregar al historial en caso de desconexión autorizada
        self.db_queries.historical_register(user_id, requested_url, 'disconnect', 'websocket')
            """