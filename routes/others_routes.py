from flask import Blueprint, jsonify, request

from json_utils import json_utils

others_bp = Blueprint('others', __name__)
json_utils_instance = json_utils()  
@others_bp.route('/change_message', methods=['POST'])
def change_message():
    data = request.json
     # Obtener los valores de 'mensaje_rule' y 'mensaje_words'
    message_rule = data.get('message_rule')
    message_word = data.get('message_word')

    if not message_rule or not message_word:
        return jsonify({"error": "Falta el mensaje"}), 400

      # Leer el archivo JSON existente usando la función importada
    mensaje_data =  json_utils_instance.read_block_messages()
    if "error" in mensaje_data:
        return jsonify(mensaje_data), 500  # Si hubo un error al leer el archivo

    # Modificar el contenido del archivo con los nuevos valores
    mensaje_data['message_rule'] = message_rule
    mensaje_data['message_word'] = message_word
    # Guardar los nuevos datos en el archivo JSON
   # Guardar los nuevos datos en el archivo JSON usando la función importada
    result = json_utils_instance.write_block_messages(mensaje_data)
    if isinstance(result, dict) and "error" in result:
        return jsonify(result), 500  # Si hubo un error al escribir en el archivo


    # Respuesta exitosa
    return jsonify({'success': True, 'message': 'Messages saved successfully'}), 200


@others_bp.route('/upload_certificate', methods=['POST'])
def upload_certificate():
    # Cargar  el certificado del cliente
    certificate = request.files.get('certificate')
    if not certificate:
        return jsonify({"error": "No se ha proporcionado un certificado"}), 400

    # Guardar el certificado en el servidor
    with open("static/assets/mitmproxy-ca-cert.pem", "wb") as f:
        f.write(certificate.read())

    return jsonify({'success': True, 'message': 'Certificate uploaded successfully'}), 200