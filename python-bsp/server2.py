from OpenSSL import SSL, crypto
from twisted.internet import ssl, reactor
from twisted.internet.protocol import Factory, Protocol

import os
from time import time

class Echo(Protocol):

    def dataReceived(self, data):
        print "Data received: " + data

        # define cases
        options = {
            "generate": self.generateCertificate,
            "sign": self.signCertificate
        }
        
        tmp = data.split(';')
        method = tmp.pop(0)
        print "method is " + method
        
        #TODO: catch unknown cases
        # delegate case to method
        result = options[method](tmp)
        
        self.transport.write(result)

    def generateCertificate(self, userDataList):
        # generate a key-pair with RSA and 2048 bits
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        
        # create a new certificate of x509 structure
        x509 = crypto.X509()
        
        # X509Name type
        subject = self.setSubject(x509.get_subject(), userDataList)
        #x509.set_subject(subject)
        
        # list of (name, value) tuples
        subComponents = subject.get_components()
        for (name, value) in subComponents:
            print name + " is " + value
        
        # cert is valid immediately
        x509.gmtime_adj_notBefore(0)
        
        # cert gets invalid after 10 years
        x509.gmtime_adj_notAfter(10*365*24*60*60)
        
        #TODO: load our CA root cert(PKCS12 type) and set subject as issuer
        # set issuer (CA) data
        x509.set_issuer(x509.get_subject())
        print "Issuer set - ACTUALLY SELF-SIGNED MODE!!!"
        
        # set user public key
        x509.set_pubkey(pkey)
        
        #TODO: which algorithm to use? (replace with sha512)
        #TODO: replace key with CA private key
        # sign the certificate
        x509.sign(pkey, 'sha256')
        print "Certificate signed - ACTUALLY SELF-SIGNED MODE!!!"
        
        # create a new PKCS12 object
        pkcs12 = crypto.PKCS12()
        
        # set the new user certificate
        pkcs12.set_certificate(x509)
        
        # insert user private key
        pkcs12.set_privatekey(pkey)
        
        # create a dump of PKCS12 and return
        return pkcs12.export()
            
    def setSubject(self, subject, data):
        #subjectVariables = {
        #    "C":    subject.C,
        #    "ST":   subject.ST,
        #    "L":    subject.L,
        #    "O":    subject.O,
        #    "OU":   subject.OU,
        #    "CN":   subject.CN
        #}
        
        for d in data:
            s = d.split('=')
            variable = s[0]
            value = s[1]
            print "Setting variable " + variable + " to " + value + " on subject"
            #subjectVariables[variable] = value
            if variable == "C":
                subject.C = value
            elif variable == "ST":
                subject.ST = value
            elif variable == "L":
                subject.L = value
            elif variable == "O":
                subject.O = value
            elif variable == "OU":
                subject.OU = value
            elif variable == "CN":
                subject.CN = value
        
        return subject
        
    def signCertificate(self, certData):

        x509 = crypto.X509()
        pkcs12 = crypto.load_pkcs12(certData)
        req = pkcs12.get_certificate()
        x509.set_subject(req.get_subject())
        x509.set_pubkey(req.get_pubkey())

        #issuer aus Datei setzen

        # cert is valid immediately
        x509.gmtime_adj_notBefore(0)
        
        # cert gets invalid after 10 years
        x509.gmtime_adj_notAfter(10*365*24*60*60)

        x509.sign(pkey, 'sha256')

        pkcs12.set_certificate(x509)

        return pkcs12.export()
        

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
