import json

# Ruta del archivo JSON
json_file_path = 'json_utils.json'
file_path = 'block_message.html'
def read_block_messages():    
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


def write_block_messages(data):
    try:
        with open(json_file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        return "Datos guardados correctamente."
    except IOError as e:
        return f"Error al escribir en el archivo: {str(e)}"
    
# Función para generar el HTML con el mensaje adecuado
def generate_block_page(message):
    block_message_data = read_block_messages()
    html_template = block_message_data.get('html_content')
    
    # Reemplazar el marcador {{message}} con el mensaje dinámico
    return html_template.replace('{{message}}', message)

def load_html_template(message_type, time, url, userIP):
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