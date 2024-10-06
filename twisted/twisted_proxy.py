from twisted.internet import reactor, ssl
from twisted.web import proxy, http
from OpenSSL import SSL
import logging
from twisted.python import log
import sys

# Habilitar el logging para ver los errores y el tráfico
log.startLogging(sys.stdout)

# Configurar logging adicional para depuración
logging.basicConfig(level=logging.DEBUG)

class ProxyRequestHandler(proxy.ProxyRequest):
    def process(self):
        logging.info(f"Intercepting request to: {self.uri}")
        print(f"Intercepting request to: {self.uri}")
        proxy.ProxyRequest.process(self)

class Proxy(proxy.Proxy):
    requestFactory = ProxyRequestHandler

class ProxyFactory(http.HTTPFactory):
    def buildProtocol(self, addr):
        return Proxy()

# Configuración del servidor proxy HTTP
def start_proxy_server():
    # Configuración del servidor HTTP
    reactor.listenTCP(8080, ProxyFactory())
    
  
    # Configuración del servidor HTTPS con certificados
    try:
        reactor.listenSSL(8443, ProxyFactory(),
                          ssl.DefaultOpenSSLContextFactory(
                              '/home/luis/Documentos/UOC/tfg/twisted.key',  # Clave privada
                              '/home/luis/Documentos/UOC/tfg/twisted.crt'))   # Certificado
        print("Proxy HTTPS en puerto 8000")
    except Exception as e:
        logging.error(f"Error al iniciar el servidor HTTPS: {e}")

    print("Proxy HTTP en puerto 8080")
    reactor.run()

if __name__ == '__main__':
    start_proxy_server()
