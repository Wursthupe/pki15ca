import sys
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler

import json
import requests

import urllib3
import certifi

#ca_certs = "./keys/intermediate.cert.pem"  # Or wherever it lives.

#http = urllib3.PoolManager(
#    cert_reqs='CERT_REQUIRED', # Force certificate check.
#    ca_certs=ca_certs,  # Path to the Certifi bundle.
#)

INDEX_TXT_DIR = "./_index_txt"
INDEX_TXT_FILE = INDEX_TXT_DIR + "/index.txt"

#https://pythonhosted.org/watchdog/api.html#watchdog.events.FileSystemEventHandler
class MyFileSystemEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print 'on_modified', event.src_path
        if not event.is_directory:
            self.send_index()

    def send_index(self):
        content = ""
        with open(INDEX_TXT_FILE, "r") as idx_file:
            content = idx_file.read().strip()
            
        index_json = json.dumps({ "data": content })
        headers = {'content-type': 'application/json'}
        
        print "Sending index.txt to VA ...", index_json
        requests.post('https://vm02.srvhub.de:8445/postIndex', data=index_json, headers=headers, verify=False)

        # You're ready to make verified HTTPS requests.
        #r = http.request('POST', 'https://vm02.srvhub.de:8445/postIndex')

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    event_handler = MyFileSystemEventHandler()
    observer = Observer()
    observer.schedule(event_handler, INDEX_TXT_DIR, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
