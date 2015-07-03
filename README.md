# PKI 42 CA

## Services
Die CA bietet 3 Services an: Zertifikate ausstellen, Certificate Signing Requests (CSR) signieren und Zertifikate zurückrufen (revoken).
Hierfür bietet sie zur Kommunikation mit der RA eine REST-Schnittstelle an, in welcher die benötigten Services aufgerufen werden können. Verwendete Methoden sind dabei PUT und POST.

### Zertifikate generieren
Die RA beantragt auf Basis der Benutzerdaten ein Zertifikat.

#### Ablauf
Durch den REST-Aufruf wird die Methode zur Generierung eines Zertifikates aufgerufen. Dabei wird für den Antragsteller ein neues RSA Schlüsselpaar mit 2048 Bits erstellt. Danach wird ein X509-Zertifikat generiert, welches mit den Benutzerdaten aus dem Antrag gefüllt wird. Dieses ist für 10 Jahre gültig. Die Intermediate CA wird als Aussteller eingetragen und der neu generierte Public Key wird dem Zertfikat angehangen. 
Da es sich hier um ein Benutzerzertifikat ohne besondere Rechte handelt, werden nur die "Basis-Extensions" gesetzt. Diese beinhalten "DigitalSignature" und "KeyEncipherment". Zudem kann das ausgestellte Zertifikat zur "ClientAuthentication" genutzt werden. 
Um Anfragen zur Gültigkeit an den richtigen OCSP-Server weiterzuleiten, wird dessen Adresse unter dem Feld "Authority Info Access" in der Extension eingetragen.
Anschließend wird das Zertifikat von der Intermediate CA signiert, wobei der Intermediate Private Key und der SHA-512-Algorithmus verwendet werden.
Dieses X509-Zertifikat wird in eine PKCS12-Struktur eingetragen, in welcher auch der Private Key des Antragstellers eingehangen wird.
Dieses PKCS12-Zertifikat wird im Binärformat an die RA zurückgegeben, welche dieses an den Benutzer weiterleiten kann.
Zusätzlich wird dieses neu ausgestellte Zertifikat noch in der index.txt-Datenbank der CA eingepflegt, über dessen Änderung nun auch die VA mittels Watcher informiert wird.

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
Durch den REST-Aufruf wird die Methode zum Signieren eines CSR aufgerufen. Dieser liest die Binärdaten aus dem Request ein und erstellt daraus ein CSR-Objekt. Dann wird ein neues X509-Zertifikat generiert, welches mit den Daten aus dem CSR gefüllt wird. Die Gültigkeitsdauer beträgt 10 Jahre.
Anschließend wird das Zertifikat von der Intermediate CA signiert, wobei der Intermediate Private Key und der SHA-512-Algorithmus verwendet werden.

TODO: Richtigen Private Key setzen und PKCS12-Struktur bauen.

Das fertig ausgestellte und signierte Zertifikat wird im Binärformat an die RA zurückgegeben, welche dieses an den Benutzer weiterleiten kann.
Zusätzlich wird dieses neu ausgestellte Zertifikat noch in der index.txt-Datenbank der CA eingepflegt, über dessen Änderung nun auch die VA mittels Watcher informiert wird.

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
Durch den REST-Aufruf wird die Methode zum Zurückrufen eines aufgerufen. Dabei wird der Common Name aus dem Request benutzt, um in der index.txt-Datenbank die passenden Einträge zu finden.
Ist dort kein Eintrag mit dem Common Name vorhanden, so wird der RA im Status zurückgemeldet, dass nichts zurückgerufen worden ist.
Sind hingegen einer oder mehrere Einträge vorhanden, so wird das entsprechende Statusfeld in der index.txt-Datenbank auf R für Revoked gesetzt. Zudem wird der Zeitpunkt des Zurückrufens eingetragen.
Der RA wird als Status zurückgemeldet, dass das Zurückrufen erfolgreich gewesen ist.
Anmerkung: Es werden alle Zertifikate zurückgerufen, auf welche der Common Name zutrifft, nicht nur eines.

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
