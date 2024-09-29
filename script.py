from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Aplica tus reglas de filtrado aquí
    if "https://campus.uoc.edu" in flow.request.pretty_url:
        flow.response = http.Response.make(
            403,  # Código de error HTTP
            b"Blocked by proxy",  # Mensaje personalizado
            {"Content-Type": "text/html"}
        )
