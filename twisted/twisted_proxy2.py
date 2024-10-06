from twisted.internet import reactor, ssl
from twisted.web import proxy, http
from twisted.internet.protocol import Protocol
from twisted.python import log
import logging

logging.basicConfig(level=logging.INFO)

class InterceptingProxyClient(proxy.ProxyClient):
    def handleHeader(self, key, value):
        logging.info(f"Intercepted header: {key}: {value}")
        proxy.ProxyClient.handleHeader(self, key, value)

    def handleResponsePart(self, buffer):
        logging.info(f"Intercepted response part: {buffer[:100]}")
        proxy.ProxyClient.handleResponsePart(self, buffer)

class InterceptingProxyClientFactory(proxy.ProxyClientFactory):
    protocol = InterceptingProxyClient

    def __init__(self, method, uri, version, headers, data, father):
        proxy.ProxyClientFactory.__init__(self, method, uri, version, headers, data, father)

class InterceptingProxyRequest(proxy.ProxyRequest):
    protocols = {'http': InterceptingProxyClientFactory, 'https': InterceptingProxyClientFactory}

    def process(self):
        logging.info(f"Intercepting request to: {self.uri.decode('utf-8')}")
        if self.method == b'CONNECT':
            self.handle_https_connect()
        else:
            proxy.ProxyRequest.process(self)

    def handle_https_connect(self):
        host, port = self.uri.split(b':')
        self.setResponseCode(200, b"Connection established")
        self.finish()
        client_factory = self.protocols['https'](self.method.decode(), host.decode(), int(port), self.clientproto.decode(), None, self)
        reactor.connectSSL(host.decode(), int(port), client_factory, ssl.ClientContextFactory())

class InterceptingProxy(proxy.Proxy):
    requestFactory = InterceptingProxyRequest

class InterceptingProxyFactory(http.HTTPFactory):
    protocol = InterceptingProxy

class ProxyServerSSLContextFactory(ssl.DefaultOpenSSLContextFactory):
    def __init__(self, privateKeyFileName, certificateFileName):
        ssl.DefaultOpenSSLContextFactory.__init__(self, privateKeyFileName, certificateFileName)

    def getContext(self):
        ctx = ssl.DefaultOpenSSLContextFactory.getContext(self)
        ctx.set_alpn_select_callback(lambda conn, protos: b'http/1.1')
        return ctx

def start_proxy_server():
    logging.info("Starting Proxy Server")
    
    ssl_context_factory = ProxyServerSSLContextFactory(
        '/home/luis/Documentos/UOC/tfg/flask_project/twisted.key',
        '/home/luis/Documentos/UOC/tfg/flask_project/twisted.crt'
    )
    
    reactor.listenTCP(8080, InterceptingProxyFactory())
    reactor.listenSSL(8443, InterceptingProxyFactory(), ssl_context_factory)
    logging.info("Proxy HTTP en puerto 8080 y Proxy HTTPS en puerto 8443")
    reactor.run()

if __name__ == '__main__':
    start_proxy_server()
