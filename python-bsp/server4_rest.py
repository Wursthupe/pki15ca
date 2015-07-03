########################################### IMPORTS ################################################
# Import OpenSSL and other utilities for HTTP connection, JSON exchange and time management.
####################################################################################################

from OpenSSL import SSL, crypto

# TWISTED INTERNET IMPORTS ARE NOT USED ANYMORE (?)
#from twisted.internet import ssl, reactor
#from twisted.internet.protocol import Factory, Protocol
#from twisted.test.test_sob import Crypto

import os
from time import time, strftime, gmtime
import json
from datetime import datetime
import random

import base64

import BaseHTTPServer

# Path to index.txt which is used as a certificate database
INDEX_TXT_PATH = "./_index_txt/index.txt"

#TODO: in production mode set to -> vm02.srvhub.de
HOST_NAME = "0.0.0.0"
#HOST_NAME = "vm02.srvhub.de"

# on production server-vm internally delegated to port 443
#PORT_NUMBER = 8444
#PORT_NUMBER = 8081
PORT_NUMBER = 80

def revoke_time_utc():
    # https://docs.python.org/2/library/time.html#time.strftime
    return strftime("%y%m%d%H%M%S", gmtime()) + "Z"

############################################## INDEX ENTRY #########################################
# Class for each Index Entry in index.txt, each holding its data fields. 
####################################################################################################

class IndexEntry(object):

    # Constructor for an index entry, location is "unknown" by default
    def __init__(self, status, expiration_date, revocation_date, serialnr, name, location = "unknown"):
        self.status = status
        self.expiration_date = expiration_date
        self.revocation_date = revocation_date
        self.serialnr = serialnr
        self.location = location
        self.name = name

    # Export an index entry as a string correctly formatted for index.txt
    def export(self): 
        tmp = self.status + "\t" + self.expiration_date + "\t" + self.revocation_date + "\t" + self.serialnr + "\t" + self.location + "\t" + self.name
        return tmp

########################################### INDEX LIST #############################################
# Class for an Index List holding all Index Entries and offering methods to work with them.
####################################################################################################

class IndexList(object):
    
    entries = []
    highest_serial_number = 0
    
    # Constructor for Index List by file path in system
    def __init__(self, file_path):
        self.file_path = file_path
        self.load_entries()
    
    def perceive_serial_number(self, entry):
        serial_no = int(entry.serialnr, 16)
        if serial_no > self.highest_serial_number:
            self.highest_serial_number = serial_no
        print "Highest sn: ", self.highest_serial_number
    
    # Load entries from file path, create an entry object and add it to the list
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

########################################### REST HANDLER ###########################################
# HTTP Request Handler managing all incoming REST requests for certificate operations.
####################################################################################################

class RestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    # Manage incoming POST request (Generate Certificate, Sign CSR)
    def do_POST(self):
        # Read input JSON with the correct length
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        # Format Header correctly
        self.send_response(200)
        # octet-stream for binary data
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()

        # Split URL path on '/' and check length
        print self.path
        pathArray = self.path.split('/')
        if len(pathArray) != 3:
            print 'Wrong Path. Correct path would be /ca/method. Methods are: generate, sign, revoke.'
            return
        
        # Get caCheck and method fields from URL
        caCheck = pathArray[1]
        method = pathArray[2]

        # Check if a CA service has been called as first argument
        if (caCheck != 'ca'):
            print 'No CA service called, CA must be first parameter (/ca/...)!'
            return
    
        # Load JSON object from input
        print "Data received: ", self.data_string
        data = json.loads(self.data_string)
        print "Data to JSON: ", data
        
        # Call the correct method passed in URL
        if (method == 'generate'):
            # TODO: Header Type must be checked if its json
            print 'Generate Certificate on POST data.'
            
            # Return pkcs12 as binary data to client
            binCert = self.generateCertificate(data)
            print base64.b64encode(binCert)
            binCert = base64.b64encode(binCert)
            json_data = json.dumps({"status":1, "certdata": binCert})
            self.wfile.write(json_data)
            
        elif (method == 'sign'):
            print 'Sign incoming CSR.'

            # Return the cert from CSR as binary data to client
            binCert = self.signCSR(self.data_string)
            self.wfile.write(binCert)
        else:
            print 'Unknown command.\nAllowed commands are: generate, sign, revoke.'

    # Manage incoming PUT request (Certificate revocation)
    def do_PUT(self):
        # Read input JSON with the correct length
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        print "Data received: ", self.data_string
        # Format Header correctly
        self.send_response(200)
        # JSON response: {"name": "value", "status": "Revoked / Not revoked"}
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        # Split URL path on '/' and check length
        print self.path
        pathArray = self.path.split('/')
        if len(pathArray) != 4:
            print 'Wrong Path. Correct path would be /ca/method. Methods are: generate, sign, revoke.'
            return
        
        # Get caCheck and method fields from URL
        caCheck = pathArray[1]
        method = pathArray[2]
        certName = pathArray[3]

        # Check if a CA service has been called as first argument
        if (caCheck != 'ca'):
            print 'No CA service called, CA must be first parameter (/ca/...)!'
            return
    
        # Load JSON object from input
        data = json.loads(self.data_string)
        print "Data received: ", data
        
        # Call the correct method passed in URL
        if (method == 'revoke'):
            # TODO: Header Type must be checked if its json
            print 'Revoke certificate with name: ', certName
            
            # Return json response with status code of revocation to client
            status_nr = self.revokeCertificate(data)
            if status_nr == 0:
                status = 'Not revoked'
            else:
                status = 'Revoked'
            status_string = '{"name": "' + certName + ', "status": "' + status + '"}'
            status_response = json.loads(status_string)
            self.wfile.write(status_response)
        else:
            print 'Unknown command.\nAllowed commands are: generate, sign, revoke.'

    # Revoke a certificate in index list based on its name
    def revokeCertificate(self, data):
        name = data["name"]
        return index_list.set_revoked(name)

    # Generate a new certificate based on user data in JSON format
    # TODO: CA used in signing and as issuer, but no cert chain yet (wrong CA certs used)
    # --> Use certs from Robin
    def generateCertificate(self, userDataList):
        # generate a key-pair with RSA and 2048 bits
        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        
        # create a new certificate of x509 structure
        x509 = crypto.X509()
        
        # set certificate version number to v3
        x509.set_version(2)
        
        # X509Name type
        self.setSubject(x509.get_subject(), userDataList)
        
        # cert is valid immediately
        x509.gmtime_adj_notBefore(0)
        
        # cert gets invalid after 10 years
        x509.gmtime_adj_notAfter(10*365*24*60*60)
        
        # retrieve next or initial serial number
        sn_int = index_list.next_serial_number()
        x509.set_serial_number(sn_int)
        
        # set issuer (CA) data
        x509.set_issuer(ca_cert.get_subject())
        
        # set user public key
        x509.set_pubkey(pkey)
        
        # SET CLIENT EXTENSIONS
        extensions = []
        
        # Set the user certificate to a 'No CA Certificate'
        basic_constraints_ext = crypto.X509Extension("basicConstraints", False, "CA:FALSE")
        extensions.append(basic_constraints_ext)
        
        cert_type_ext = crypto.X509Extension("nsCertType", False, "client, email")
        extensions.append(cert_type_ext)
        
        ns_comment_ext = crypto.X509Extension("nsComment", False, "OpenSSL Generated Client Certificate")
        extensions.append(ns_comment_ext)
        
        subj_key_ident_ext = crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca_cert)
        extensions.append(subj_key_ident_ext)
        
        auth_key_ident_ext = crypto.X509Extension("authorityKeyIdentifier", False, "keyid", issuer=ca_cert)
        extensions.append(auth_key_ident_ext)
        
        # Set the key usage of the user certificate to 'digitalSignature and keyEncipherment'
        key_usage_ext = crypto.X509Extension("keyUsage", True, "nonRepudiation, digitalSignature, keyEncipherment")
        extensions.append(key_usage_ext)
        
        # Set the extended key usage of the user certificate to 'clientAuthentication'
        extended_key_usage_ext = crypto.X509Extension("extendedKeyUsage", False, "clientAuth, emailProtection")
        extensions.append(extended_key_usage_ext)
        
        # Set the info access path to the OCSP URL
        authority_info_access_ext = crypto.X509Extension("authorityInfoAccess", False, "OCSP;URI:http://vm02.srvhub.de:3000")
        extensions.append(authority_info_access_ext)
        
        # Add all extensions to the new certificate
        x509.add_extensions(extensions)
        
        # sign the certificate
        x509.sign(ca_key, 'sha512')
        
        # TODO: temporary cert, just for test reasons (should be removed in final version)
        with open("tmp.crt", "w") as tmp_file:
            tmp_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, x509))
            
        # create a new PKCS12 object
        pkcs12 = crypto.PKCS12()

        # set ca certificate chain
        cacert = []
        cacerts.append(ca_cert)
        pkcs12.set_ca_certificates(cacerts)
        
        # set the new user certificate
        pkcs12.set_certificate(x509)
        
        # insert user private key
        pkcs12.set_privatekey(pkey)
        
        # revoke before signed/generated certificates
        name = export_x509name(x509.get_subject())
        index_list.set_revoked(name)
        
        # add certificate to the index-list
        index_list.add_entry(x509)
        
        # create a dump of PKCS12 and return
        return pkcs12.export()
            
    # Insert the data from a JSON object into a certificate
    def setSubject(self, subject, data):
        subject.C = data["C"]
        subject.ST = data["ST"]
        subject.L = data["L"]
        subject.O = data["O"]
        subject.OU = data["OU"]
        subject.CN = data["CN"]
        
        return subject
    
    # Sign an incoming CSR from RA and return the signed certificate in binary format
    def signCSR(self, csrData):
        # Load the CSR from binary input
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, self.data_string)
        print 'CSR loaded from subject: ', csr.get_subject()
        
        # Get data from CSR and insert it into new cert
        cert = crypto.X509()
        cert.set_subject(csr.get_subject())
        cert.set_serial_number(index_list.next_serial_number())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        
        extensions = []
        
        # Set the user certificate to a 'No CA Certificate'
        basic_constraints_ext = crypto.X509Extension("basicConstraints", False, "CA:FALSE")
        extensions.append(basic_constraints_ext)
        
        cert_type_ext = crypto.X509Extension("nsCertType", False, "server")
        extensions.append(cert_type_ext)
        
        ns_comment_ext = crypto.X509Extension("nsComment", False, "OpenSSL Generated Server Certificate")
        extensions.append(ns_comment_ext)
        
        subj_key_ident_ext = crypto.X509Extension("subjectKeyIdentifier", False, "hash")
        extensions.append(subj_key_ident_ext)
        
        auth_key_ident_ext = crypto.X509Extension("authorityKeyIdentifier", False, "keyid, issuer:always")
        extensions.append(auth_key_ident_ext)
        
        # Set the key usage of the user certificate to 'digitalSignature and keyEncipherment'
        key_usage_ext = crypto.X509Extension("keyUsage", True, "digitalSignature, keyEncipherment")
        extensions.append(key_usage_ext)
        
        # Set the extended key usage of the user certificate to 'clientAuthentication'
        extended_key_usage_ext = crypto.X509Extension("extendedKeyUsage", False, "serverAuth")
        extensions.append(extended_key_usage_ext)
        
        # Set the info access path to the OCSP URL
        authority_info_access_ext = crypto.X509Extension("authorityInfoAccess", False, "OCSP;URI:http://vm02.srvhub.de:3000")
        extensions.append(authority_info_access_ext)
        
        # Add all extensions to the new certificate
        x509.add_extensions(extensions)
        
        # Sign this new cert with the CA
        cert.sign(ca_key, 'sha512')
        
        # Add the new cert to index.txt databse
        index_list.add_entry(cert)
        #pkcs12 = crypto.PKCS12()
        #pkcs12.set_certificate(cert)
        
        # TODO: correct this line!
        #pkcs12.set_privatekey(?)

# Export data fields of a certificate as a string in X509-Format (/C=XXX/ST=XXX/...)
def export_x509name(x509name):
    #/C=DE/ST=NRW/L=Minden/O=FH Bielefeld/OU=FB Technik/CN=hlampe@fh-bielefeld.de
    tmp = "/C=" + x509name.C # countryName
    tmp = tmp + "/ST=" + x509name.ST # stateOrProvinceName
    tmp = tmp + "/L=" + x509name.L # localityName
    tmp = tmp + "/O=" + x509name.O # organizationName
    tmp = tmp + "/OU=" + x509name.OU # organizationalUnitName
    tmp = tmp + "/CN=" + x509name.CN # commonName

    return tmp

############################################## MAIN ################################################
# Start the server, load the CA certificate and key. Start RestHandler when a client connects.
####################################################################################################

#TODO: Check if paths match eventually new folder structure
# Use .crt and .key files instead of .pem
cert_file = open("./keys/intermediate.cert.pem")
key_file = open("./keys/intermediate.key.pem")
ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())
cert_file.close()
key_file.close()
print "certificates and keys of ca loaded"
        
if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), RestHandler)
    #TODO: Insert the communication cert of CA here to use it for HTTPS / SSL communication
    # httpd.socket = ssl.wrap_socket (httpd.socket, certfile='path/to/localhost.pem', server_side=True)
    print "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    try:
        httpd.serve_forever()

    # Handle Key Interrupt for a clean stop of the server
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)
