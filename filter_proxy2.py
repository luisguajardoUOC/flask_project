"""
Use mitmproxy's filter pattern in scripts.
"""

from __future__ import annotations

import logging

from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.addonmanager import Loader
import json

# Palabras clave sospechosas en el contenido de las respuestas
explicit_keywords = [
    "porn", "sex", "nude", "erotic", "hardcore"
]
class Filter:
    # Define un filtro (flowfilter.TFilter) que será utilizado para comparar los flujos que pasan por el proxy.
    filter: flowfilter.TFilter
    

    def __init__(self):
            self.blocked_sites = []
            self.filter = None 
            # Cargar los sitios bloqueados desde el archivo JSON
            try:
                with open("blocked_websites.json", "r") as file:
                    blocked_data = json.load(file)  # Cargar la lista de diccionarios
                    # Procesar cada entrada del JSON y guardar la URL junto con otros parámetros
                    self.blocked_sites = [
                        {"url": item["url"], "category": item.get("category"), "reason": item.get("reason")}
                        for item in blocked_data
                    ]
                    logging.info(f"Loaded blocked sites: {self.blocked_sites}")
            except FileNotFoundError:
                logging.error("blocked_websites.json not found!")
            except json.JSONDecodeError:
                logging.error("Error decoding blocked_websites.json!")

            # Cargar las palabras clave maliciosas desde malicious_filter.json
            try:
                with open("malicious_filter.json", "r") as file:
                    filter_data = json.load(file)
                    self.malicius_keywords = filter_data["keywords"]
                    logging.info(f"Loaded malicious keywords: {self.malicius_keywords}")
            except FileNotFoundError:
                logging.error("malicious_filter.json not found!")
            except json.JSONDecodeError:
                logging.error("Error decoding malicious_filter.json!")

            # Cargar las páginas autorizadas desde authorized_websites.json
            try:
                with open("authorized_websites.json", "r") as file:
                    authorized_data = json.load(file)
                    self.authorized_sites = [item["url"] for item in authorized_data]
                    logging.info(f"Loaded authorized sites: {self.authorized_sites}")
            except FileNotFoundError:
                logging.error("authorized_websites.json not found!")
            except json.JSONDecodeError:
                logging.error("Error decoding authorized_websites.json!")

# respuesta HTTP
    def request(self, flow: http.HTTPFlow) -> None:
        for site in self.blocked_sites:
            if site["url"] in flow.request.pretty_url:
                flow.response = http.Response.make(
                    403,  # (optional) status code
                    b"Access to this site is blocked by the proxy.",  # (optional) content
                    {"Content-Type": "text/html"},  # (optional) headers
                )
                flow.metadata["blocked"] = True  # Usar una propiedad personalizada para marcar la solicitud como bloqueada
                return  # Detener el flujo aquí si se bloquea la solicitud
        
        

# respuesta HTT
    def response(self, flow: http.HTTPFlow) -> None:
         # Verificar si la URL está en la lista de sitios autorizados
        if any(site in flow.request.pretty_url for site in self.authorized_sites):
            logging.info(f"Skipping response content analysis for authorized site: {flow.request.pretty_url}")
            return  # No analizar ni bloquear el contenido de sitios autorizados

        # Si la solicitud fue marcada como bloqueada, no continuar
        if flow.metadata.get("blocked", False):
            logging.info(f"Skipping response for blocked request: {flow.request.pretty_url}")
            return  # Detener si la solicitud fue bloqueada en request

        # Si no existe una respuesta (puede haber sido bloqueada), salir
        if flow.response is None:
            return
        # Detectar palabras clave maliciosas en el contenido de la respuesta
        content = flow.response.get_text(strict=False)
        # Buscar si alguna palabra clave está en el contenido de la respuesta
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


addons = [Filter()]