from OpenSSL import SSL, crypto
from twisted.internet import ssl, reactor
from twisted.internet.protocol import ClientFactory, Protocol
import json
import random

def get_random_word(wordLen):
    word = ''
    for i in range(wordLen):
        word += random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
    return word

class EchoClient(Protocol):
    def connectionMade(self):
        typ = "generate"
        staat = "DE"
        land = "NRW"
        ort = "Minden"
        org = "FH Bielefeld"
        orgUnit = "Technik"
        email = get_random_word(10) + "@" + get_random_word(10) + "." + get_random_word(3)

        data = json.dumps({"METHOD": typ, "C": staat, "ST": land, "L": ort, "O": org, "OU": orgUnit, "CN": email});

        print data

        self.transport.writeSequence(data)
        

    def dataReceived(self, data):
        print "Server said:", data
        
        f = open("test.pfx","w") #opens file with name of "test.txt"
        f.write(data)
        f.close()
        
        # load certificate data and print something
        pkcs12 = crypto.load_pkcs12(data)
        x509 = pkcs12.get_certificate()
        
        subject = x509.get_subject()
        
        # list of (name, value) tuples
        subComponents = subject.get_components()
        for (name, value) in subComponents:
            print name + " is " + value
            
        print subject
        print subject.der()
        
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
    
