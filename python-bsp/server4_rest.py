from OpenSSL import SSL, crypto
from twisted.internet import ssl, reactor
from twisted.internet.protocol import Factory, Protocol

import os
from time import time, strftime, gmtime
import json
from datetime import datetime
import random

import BaseHTTPServer
from twisted.test.test_sob import Crypto

INDEX_TXT_PATH = "index.txt"

#TODO: in production mode set to -> vm02.srvhub.de
HOST_NAME = "localhost"

# on production server-vm internally delegated to port 443
PORT_NUMBER = 8444

def revoke_time_utc():
    # https://docs.python.org/2/library/time.html#time.strftime
    return strftime("%y%m%d%H%M%S", gmtime()) + "Z"

class IndexEntry(object):
    def __init__(self, status, expiration_date, revocation_date, serialnr, name, location = "unknown"):
        self.status = status
        self.expiration_date = expiration_date
        self.revocation_date = revocation_date
        self.serialnr = serialnr
        self.location = location
        self.name = name

    def export(self): 
        tmp = self.status + "\t" + self.expiration_date + "\t" + self.revocation_date + "\t" + self.serialnr + "\t" + self.location + "\t" + self.name
        return tmp

class IndexList(object):
    
    entries = []
    highest_serial_number = 0
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.load_entries()
    
    def perceive_serial_number(self, entry):
        serial_no = int(entry.serialnr, 16)
        if serial_no > self.highest_serial_number:
            self.highest_serial_number = serial_no
        print "Highest sn: ", self.highest_serial_number
    
    def load_entries(self):
        self.entries = []
        
        # load list from index.txt
        with open(self.file_path, "r") as idx_file:
            text = idx_file.read().strip()
            lines = text.splitlines()
            for line in lines:
                entry = self.create_entry(line.strip())
                self.entries.append(entry)
                self.perceive_serial_number(entry)

    def create_entry(self, idx_line):
        line_items = idx_line.split("\t")
        status = line_items[0]
        expiration_date = line_items[1]
        revocation_date = line_items[2]
        serialnr = line_items[3]
        location = line_items[4]
        name = line_items[5]

        entry = IndexEntry(status, expiration_date, revocation_date, serialnr, name, location)
        return entry

    def get_entry_indices(self, name):
        #http://stackoverflow.com/questions/3013449/list-filtering-list-comprehension-vs-lambda-filter
        return [idx for idx, e in enumerate(self.entries) if e.name == name]
    
    def next_serial_number(self):
        self.highest_serial_number = self.highest_serial_number + 1
        print "Next serial number: ", self.highest_serial_number
        return self.highest_serial_number

    def add_entry(self, x509):
        name = export_x509name(x509.get_subject())
        sn_int = x509.get_serial_number()
        sn_hex = "%02X" % sn_int
        line = "V\t" + str(x509.get_notAfter()) + "\t\"empty\"\t" + str(sn_hex) + "\tunknown\t" + name + "\n"

        print "Adding", line, "to", self.file_path
        with open(self.file_path, "a") as idx_file:
            idx_file.write(line)
        
        self.load_entries()

    def set_revoked(self, name):
        # change status of an entry to revoked
        # expiration date must be set here
        entry_indices = self.get_entry_indices(name)
        if len(entry_indices) == 0:
            return 0
        
        for idx in entry_indices:
            entry = self.entries[idx]
            entry.status = "R"
            entry.revocation_date = revoke_time_utc()
            print name, "revoked at", entry.revocation_date
            self.entries[idx] = entry
            
        with open(self.file_path, "w") as idx_file:
            idx_file.write(self.export())
        
        return 1

    def export(self):
        # export list in standard format to file
        content = ""
        for entry in self.entries:
            content = content + entry.export() + "\n"
        return content

index_list = IndexList(INDEX_TXT_PATH)
print "INITIAL list:\n", index_list.export()

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_POST(self):
        # Read input JSON with the correct length
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        # Format Header correctly
        self.send_response(200)
        # octet-stream for binary data
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()

        print self.path
        pathArray = self.path.split('/')
        if len(pathArray) != 3:
            print 'Wrong Path. Correct path would be /ca/method. Methods are: generate, sign, revoke.'
            return
        
        caCheck = pathArray[1]
        method = pathArray[2]

        if (caCheck != 'ca'):
            print 'No CA service called, CA must be first parameter (/ca/...)!'
            return
        
        if (method == 'generate'):
            # TODO: Header Type must be checked if its json
            print 'Generate Certificate on POST data.'
            
            # Load JSON object from input
            data = json.loads(self.data_string)
            print "Data received: ", data
            
            # Print received fields
            #print 'C: ', data['C']
            #print 'ST: ', data['ST']
            #print 'L: ', data['L']
            #print 'O: ', data['O']
            #print 'OU: ', data['OU']
            #print 'CN: ', data['CN']
            
            # Return pkcs12 as binary data to client
            binCert = self.generateCertificate(data)
            self.wfile.write(binCert)
            
            # VA needs to be triggered about new index.txt
            
            
        elif (method == 'sign'):
            print 'Sign incoming CSR.'
            #self.signCSR(self.data_string)
            print ca_cert.get_subject()
        elif (method == 'revoke'):
            print 'Revoke a certificate and tell VA.'
        else:
            print 'Unknown command.\nAllowed commands are: generate, sign, revoke.'

    def revokeCertificate(self, data):
        name = data["name"]
        return index_list.set_revoked(name)

    def generateCertificate(self, userDataList):
        # generate a key-pair with RSA and 2048 bits
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        
        # create a new certificate of x509 structure
        x509 = crypto.X509()
        
        # X509Name type
        self.setSubject(x509.get_subject(), userDataList)
        
        # cert is valid immediately
        x509.gmtime_adj_notBefore(0)
        
        # cert gets invalid after 10 years
        x509.gmtime_adj_notAfter(10*365*24*60*60)
        
        # retrieve next or initial serial number
        name = export_x509name(x509.get_subject())
        sn_int = index_list.next_serial_number()
        x509.set_serial_number(sn_int)
        
        #TODO: load our CA root cert(PKCS12 type) and set subject as issuer
        # set issuer (CA) data
        x509.set_issuer(x509.get_subject())
        #print "Issuer set - ACTUALLY SELF-SIGNED MODE!!!"
        
        # set user public key
        x509.set_pubkey(pkey)
        
        #TODO: which algorithm to use? (replace with sha512)
        #TODO: replace key with CA private key
        # sign the certificate
        x509.sign(pkey, 'sha256')
        #print "Certificate signed - ACTUALLY SELF-SIGNED MODE!!!"
        
        # create a new PKCS12 object
        pkcs12 = crypto.PKCS12()
        
        # set the new user certificate
        pkcs12.set_certificate(x509)
        
        # insert user private key
        pkcs12.set_privatekey(pkey)
        
        # revoke before signed/generated certificates
        index_list.set_revoked(name)
        
        # add certificate to the index-list
        index_list.add_entry(x509)
        
        # create a dump of PKCS12 and return
        return pkcs12.export()
            
    def setSubject(self, subject, data):
        subject.C = data["C"]
        subject.ST = data["ST"]
        subject.L = data["L"]
        subject.O = data["O"]
        subject.OU = data["OU"]
        subject.CN = data["CN"]
        
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
        
        # add certificate to the index-list
        index_list.add_entry(x509)

        pkcs12.set_certificate(x509)

        return pkcs12.export()
    
    def signCSR(self, csrData):
        csr = crypto.load_certificate_request(crypto.FILETYPE_ASN1, self.data_string)
        cert = crypto.X509()
        cert.set_subject(csr.get_subject())
        
        cert.set_serial_number(index_list.next_serial_number())
        
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        #cert.set_issuer()
        cert.set_pubkey(csr.get_pubkey())
        
        # TODO: correct this line!
        #cert.sign(?, 'sha256')
        
        index_list.add_entry(cert)
        pkcs12 = crypto.PKCS12()
        pkcs12.set_certificate(cert)
        
        # TODO: correct this line!
        #pkcs12.set_privatekey(?)

def export_x509name(x509name):
    #/C=DE/ST=NRW/L=Minden/O=FH Bielefeld/OU=FB Technik/CN=hlampe@fh-bielefeld.de
    tmp = "/C=" + x509name.C # countryName
    tmp = tmp + "/ST=" + x509name.ST # stateOrProvinceName
    tmp = tmp + "/L=" + x509name.L # localityName
    tmp = tmp + "/O=" + x509name.O # organizationName
    tmp = tmp + "/OU=" + x509name.OU # organizationalUnitName
    tmp = tmp + "/CN=" + x509name.CN # commonName

    return tmp

if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    # httpd.socket = ssl.wrap_socket (httpd.socket, certfile='path/to/localhost.pem', server_side=True)
    print "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    try:
        #TODO: correct this line
        #ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, "./keys/ca/ca-cert.pem")
        #ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, "./keys/ca/ca-key.pem")
        #print "certificates and keys of ca loaded"
        
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)
