# PKI 42 CA

## Services
Die CA bietet 3 Services an: Zertifikate ausstellen, Certificate Signing Requests (CSR) signieren und Zertifikate zurückrufen (revoken).
Hierfür bietet sie zur Kommunikation mit der RA eine REST-Schnittstelle an, in welcher die benötigten Services aufgerufen werden können. Verwendete Methoden sind dabei PUT und POST.

### Zertifikate generieren
Die RA beantragt auf Basis der Benutzerdaten ein Zertifikat.

#### Ablauf

#### REST-Aufruf
REST-Methode: POST
Die RA schickt die Benutzerdaten im JSON-Format zur CA.
Die Response ist ein generiertes Zertifikat im Binärformat.
JSON-Aufbau der Daten, welche die RA schickt:

```bash
{"C": "DE", "ST": "NRW", "L": "Minden", "O": "FH Bielefeld", "OU": "MIF", "CN": "vm02.srvhub.de"}
```

Die URL zum Aufruf der REST-API lautet hier:

```bash
/ca/generate
```

### CSR signieren
Die RA schickt einen Certificate Signing Request zur CA und bittet um das Signieren von diesem.

#### Ablauf

#### REST-Aufruf
REST-Methode: POST
Die RA schickt den CSR im Binärformat zur CA.
Die Response ist ein generiertes Zertifikat im Binärformat, welches auf den Daten aus dem CSR aufbaut und dieses schließlich als CA signiert.

Die URL zum Aufruf der REST-API lautet hier:

```bash
/ca/sign
```

### Zertifikat zurückrufen (revoken)
Die RA stellt den Antrag, ein Zertifikat zurückzurufen, sodass dieses als ungültig gekennzeichent wird.

#### Ablauf

#### REST-Aufruf
REST-Methode: PUT
Die RA schickt den Revokation Request als JSON zur CA.
Aufbau der JSON-Daten, die die RA schickt:

```bash
{"name": "common name to revoke"}
```

Die Response liegt ebenfalls im JSON-Format vor und erweitert den gestellten Request um einen Status, ob das Zurückrufen des Zertifikates erfolgreich gewesen ist oder nicht.
Aufbau der JSON-Daten aus der Response:

```bash
{"name": "common name to revoke", "status": "Revoked"}
{"name": "common name to revoke", "status": "Not revoked"}
```

Die URL zum Aufruf der REST-API lautet hier:

```bash
/ca/revoke
```
