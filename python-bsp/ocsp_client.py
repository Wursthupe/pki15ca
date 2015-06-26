from OpenSSL import SSL, crypto
from twisted.internet import ssl, reactor
from twisted.internet.protocol import ClientFactory, Protocol
import json

class EchoClient(Protocol):
    def connectionMade(self):
        typ = "ocsprqst"
        data = json.dumps({"METHOD": typ});
        self.transport.writeSequence(data)
        
    def dataReceived(self, data):
        print "Server said:", data
        self.transport.loseConnection()

class EchoClientFactory(ClientFactory):
    protocol = EchoClient

    def clientConnectionFailed(self, connector, reason):
        print "Connection failed - goodbye!"
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        print "Connection lost - goodbye!"
        reactor.stop()

class CtxFactory(ssl.ClientContextFactory):
    def getContext(self):
        self.method = SSL.SSLv23_METHOD
        ctx = ssl.ClientContextFactory.getContext(self)
        ctx.use_certificate_file('keys/zertifikat-pub.pem')

        # Worfuer brauchen wir das ???
        ctx.use_privatekey_file('keys/zertifikat-key.pem')

        return ctx

if __name__ == '__main__':
    factory = EchoClientFactory()
    reactor.connectSSL('localhost', 8000, factory, CtxFactory())
    reactor.run()
    
