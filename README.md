# PKI 42 CA

## Services
Die CA bietet 3 Services an: Zertifikate ausstellen, Certificate Signing Requests (CSR) signieren und Zertifikate zurückrufen (revoken).
Hierfür bietet sie zur Kommunikation mit der RA eine REST-Schnittstelle an, in welcher die benötigten Services aufgerufen werden können. Verwendete Methoden sind dabei PUT und POST.

### Zertifikate generieren
Die RA beantragt auf Basis der Benutzerdaten ein Zertifikat.

#### Ablauf
DASJKDsansdklasndlkjsandkj

#### REST-Aufruf
REST-Methode: POST
Die RA schickt die Benutzerdaten im JSON-Format zur CA
Die Response ist ein generiertes Zertifikat im Binärformat
JSON-Aufbau der Daten, welche die RA schickt:

```bash
{"C": "DE“, "ST": “NRW“, "L":“ Minden“, "O": “FH Bielefeld“, "OU": “MIF“, "CN":“ vm02.srvhub.de“}
```

Die URL zum Aufruf der REST-API lautet hier:

```bash
/ca/generate
```



