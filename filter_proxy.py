import json
from mitmproxy import http, ctx

# Definir la variable global antes de usarla en las funciones
blocked_websites = []

# Recibir la lista de sitios bloqueados desde un archivo JSON pasado como argumento
def load_blocked_websites(path):
    global blocked_websites
    print(f"Loading blocked websites from: {path}")  # Depuración
    try:
        with open(path, 'r') as f:
            blocked_websites = json.load(f)
        print(f"Blocked websites loaded: {blocked_websites}")
    except Exception as e:
        print(f"Failed to load blocked websites JSON: {str(e)}")
        blocked_websites = []

# Este método es llamado cuando mitmdump se inicia.
def load(loader):
    print("Proxy started, loading blocked websites...")
    
    # Obtener los argumentos adicionales pasados al script (ruta del archivo JSON)
    if len(ctx.options.scripts) > 1:
        path = ctx.options.scripts[1]
        load_blocked_websites(path)
    else:
        print("No JSON file provided to load blocked websites.")

# Este método se llama en cada solicitud.
def request(flow: http.HTTPFlow) -> None:
    global blocked_websites
    url = flow.request.pretty_url
    print(f"Request made to URL: {url}")

    if not blocked_websites:
        print("Blocked websites list is empty or not loaded correctly.")
    
    for blocked_site in blocked_websites:
        print(f"Checking if {blocked_site} is in {url}")
        if blocked_site in url:
            print(f"Blocking site: {url}")
            flow.response = http.Response.make(
                403, 
                b"Access to this site is blocked by the proxy.",
                {"Content-Type": "text/html"}
            )
            return

    print(f"Allowing site: {url}")


