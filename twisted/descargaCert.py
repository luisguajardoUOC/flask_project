import json
from mitmproxy import http

# Ruta del archivo JSON y del certificado raíz
CERTIFICATE_FILE = "/home/usuario/.mitmproxy/mitmproxy-ca-cert.pem"
IPS_FILE = "ips_with_cert.json"

# Cargar las IPs desde el archivo JSON
def load_ips():
    try:
        with open(IPS_FILE, "r") as file:
            data = json.load(file)
            return set(data["ips_with_certificate"])
    except (FileNotFoundError, json.JSONDecodeError):
        # Si no existe el archivo o está vacío, devolvemos un conjunto vacío
        return set()

# Guardar las IPs en el archivo JSON
def save_ips(ips):
    with open(IPS_FILE, "w") as file:
        json.dump({"ips_with_certificate": list(ips)}, file)

# Verificar si es la primera conexión
def is_first_connection(client_ip, ips):
    return client_ip not in ips

# Registrar la IP del cliente en el archivo JSON
def register_client_ip(client_ip, ips):
    ips.add(client_ip)
    save_ips(ips)

def request(flow: http.HTTPFlow) -> None:
    # Obtener la IP del cliente
    client_ip = flow.client_conn.peername[0]
    
    # Cargar el conjunto de IPs que ya han recibido el certificado
    ips_with_certificate = load_ips()
    
    # Verificar si es la primera conexión del cliente
    if is_first_connection(client_ip, ips_with_certificate):
        # Enviar el certificado
        with open(CERTIFICATE_FILE, "rb") as f:
            cert_data = f.read()

        flow.response = http.Response.make(
            200,  # Código de respuesta HTTP
            cert_data,  # Certificado en el cuerpo de la respuesta
            {"Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"}
        )
        
        # Registrar la IP del cliente
        register_client_ip(client_ip, ips_with_certificate)
    else:
        # Aquí continúa el flujo normal de mitmproxy, revisando bloqueos
        if "blocked.com" in flow.request.pretty_url:
            flow.response = http.Response.make(
                403,  # Código de respuesta HTTP para bloqueos
                b"Access Denied: This URL is blocked.",  # Mensaje de bloqueo
                {"Content-Type": "text/plain"}
            )
        else:
            # Dejar pasar el tráfico sin cambios si no está bloqueado
            pass
