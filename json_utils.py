import json

# Ruta del archivo JSON
json_file_path = 'static/assets/json_utils.json'
file_path = 'static/assets/block_message.html'
# Ruta del archivo JSON y del certificado raíz
CERTIFICATE_FILE = "static/assets/mitmproxy-ca-cert.pem"
IPS_FILE = "static/assets/ips_with_cert.json"
class json_utils:
    def __init__(self):
        pass
    def read_block_messages(self):
        try:
            with open(json_file_path, 'r') as json_file:
                data = json.load(json_file)
                return data
        except FileNotFoundError:
            # Devuelve un mensaje por defecto si no existe el archivo
            return {
                "message_rule": "Access blocked by the proxy",
                "message_word": "Malicious content detected"
            }
        except json.JSONDecodeError:
            return "Error al decodificar el archivo JSON."
        except Exception as e:
            return f"Error inesperado: {str(e)}"


    def write_block_messages(self,data):
        try:
            with open(json_file_path, 'w') as json_file:
                json.dump(data, json_file, indent=4)
            return "Datos guardados correctamente."
        except IOError as e:
            return f"Error al escribir en el archivo: {str(e)}"

    # Función para generar el HTML con el mensaje adecuado
    def generate_block_page(self,message):
        block_message_data = self.read_block_messages()
        html_template = block_message_data.get('html_content')

        # Reemplazar el marcador {{message}} con el mensaje dinámico
        return html_template.replace('{{message}}', message)

    def load_html_template(self,message_type, time, url, userIP):
        try:
            with open(file_path, 'r') as file:
                html_content = file.read()
                #Reemplazar los marcadores con los valores proporcionados
                html_content = html_content.replace('{{message}}', message_type)
                html_content = html_content.replace('{{time}}', time)
                html_content = html_content.replace('{{url}}', url)
                html_content = html_content.replace('{{userIP}}', userIP)
                return html_content
        except FileNotFoundError:
            return "<html><body><h1>Template not found</h1></body></html>"
        

    # Cargar las IPs desde el archivo JSON
    # Ruta del archivo JSON y del certificado raíz
    #CERTIFICATE_FILE = "assets/mitmproxy-ca-cert.pem"
    #IPS_FILE = "/assetsips_with_cert.json"
    def load_ips(self):
        try:
            with open(IPS_FILE, "r") as file:
                data = json.load(file)
                return set(data["ips_with_certificate"])
        except (FileNotFoundError, json.JSONDecodeError):
            # Si no existe el archivo o está vacío, devolvemos un conjunto vacío
            return set()

    # Guardar las IPs en el archivo JSON
    def save_ips(self,ip):
        with open(IPS_FILE, "w") as file:
            json.dump({"ips_with_certificate": list(ip)}, file)

    # Verificar si es la primera conexión
    def is_first_connection(self,client_ip, ips_with_certificate):
        return client_ip not in ips_with_certificate

    # Registrar la IP del cliente en el archivo JSON
    def register_client_ip(self, client_ip):
        # Cargar las IPs actuales desde el archivo JSON
        ips_with_certificate = self.load_ips()    
        # Añadir la nueva IP al conjunto de IPs
        ips_with_certificate.add(client_ip)  # 'add()' es un método de 'set'       
        # Guardar el nuevo conjunto de IPs en el archivo JSON
        self.save_ips(ips_with_certificate)

    def load_certificates(self):
        with open(CERTIFICATE_FILE, "rb") as file:
            return file.read()