import sys
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, FileSystemEventHandler

import json
import requests

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
        
        print "Sending index.txt to VA ...", index_json
        requests.post('http://vm02.srvhub.de:8000/postIndex', data=index_json)

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
