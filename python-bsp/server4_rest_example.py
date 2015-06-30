from OpenSSL import SSL, crypto
from twisted.internet import ssl, reactor
from twisted.internet.protocol import Factory, Protocol

import os
from time import strftime, gmtime
from datetime import datetime
import random

from twisted.test.test_sob import Crypto

import time
import BaseHTTPServer
import json
 
HOST_NAME = 'localhost' # !!!REMEMBER TO CHANGE THIS!!!
PORT_NUMBER = 8444 # Maybe set this to 9000.

class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_HEAD(s):
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
    def do_GET(s):
        """Respond to a GET request."""
        print("Content of s: ", s)
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        s.wfile.write("<html><head><title>Title goes here.</title></head>")
        s.wfile.write("<body><p>This is a test.</p>")
        # If someone went to "http://something.somewhere.net/foo/bar/",
        # then s.path equals "/foo/bar/".

        if s.path == "/cert":
            s.wfile.write("Cert Tree accessed.")
        elif s.path == "/csr":
            s.wfile.write("CSR Tree accessed.")

        s.wfile.write("<p>You accessed path: %s</p>" % s.path)
        s.wfile.write("</body></html>")

    def do_POST(self):
        # Read input JSON with the correct length
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        # Format Header correctly
        self.send_response(200)
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
        else:
            if (method == 'generate'):
                print 'Generate Certificate on POST data.'
                print self.data_string
                # Load JSON object from input
                
                data = json.loads(self.data_string)
                print data
                
                # Print received fields
                print 'C: ', data['C']
                print 'ST: ', data['ST']
                print 'L: ', data['L']
                print 'O: ', data['O']
                print 'OU: ', data['OU']
                print 'CN: ', data['CN']
            elif (method == 'sign'):
                print 'Sign incoming CSR.'
            elif (method == 'revoke'):
                print 'Revoke a certificate and tell VA.'
            else:
                print 'Unknown command.\nAllowed commands are: generate, sign, revoke.'

if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
    # httpd.socket = ssl.wrap_socket (httpd.socket, certfile='path/to/localhost.pem', server_side=True)
    print time.asctime(), "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print time.asctime(), "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)
