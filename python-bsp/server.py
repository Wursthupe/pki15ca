from OpenSSL import SSL
from twisted.internet import ssl, reactor
from twisted.internet.protocol import Factory, Protocol

import os
from time import time

class Echo(Protocol):

    def dataReceived(self, data):
        ts = getTimestamp()
        privKeyFileName = self.generateClientPrivateKey(ts)
        self.transport.write(data)

    # generates client's private key and returns it's file path
    def generateClientPrivateKey(self, ts):
        keyFileName = addTimestamp(ts, 'clientPrivKey.pem')
        os.system('openssl genrsa -out ' + keyFileName + ' 2048')
        return keyFileName

    def generateCSR(self, ts, privKeyFileName):
        # openssl req -new -key zertifikat-key.pem -out zertifikat.csr -sha512
        return 0
        
    
    def processCSR(self, ts, caRootFile, caKeyFile, csrFile):
        outputCertFile = addTimestamp(ts, 'clientCert.pem')
        os.system(
            'openssl x509 -req -in ' + csrFile + ' -CA ' + caRootFile 
            + ' -CAkey ' + caKeyFile + ' -CAcreateserial -out '
            + outputCertFile + ' -days 365 -sha512') 

def verifyCallback(connection, x509, errnum, errdepth, ok):
    if not ok:
        print 'invalid cert from subject:', x509.get_subject()
        return False
    else:
        print "Certs are fine", x509.get_subject()
    return True

def getTimestamp():
    return str(int(round(time() * 1000)))

def addTimestamp(millis, name):
    print millis + '_' + name

if __name__ == '__main__':
    factory = Factory()
    factory.protocol = Echo

    os.system("echo 'Server started...'")

    myContextFactory = ssl.DefaultOpenSSLContextFactory(
        'keys/ca-key.pem', 'keys/ca-root.pem'
        )

    ctx = myContextFactory.getContext()

    # SSL.VERIFY_PEER: Verifizierung des verwendeten SSL-Certs vorraussetzen (default=true)
    # VERIFY_FAIL_IF_NO_PEER_CERT: Vorgang wird abgebrochen, wenn die Verbindung ohne Zertifikat 
    #     verwendet wird (setzt obigen Parameer vorraus!)
    ctx.set_verify(
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        verifyCallback
        )

    # Since we have self-signed certs we have to explicitly
    # tell the server to trust them.
    ctx.load_verify_locations("keys/ca-root.pem")

    reactor.listenSSL(8000, factory, myContextFactory)
    reactor.run()
