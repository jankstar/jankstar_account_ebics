# Lokaler EBICS-Testserver

`ebics_testserver.py` verhält sich wie eine Bank mit EBICS 3.0 (H005):
HEV, INI, HIA, HPB und BTD mit Quittung. Damit lassen sich die Blöcke
E06–E09 in der Tryton-Oberfläche von Hand testen, ohne echte Bank.

Kern ist die simulierte Bank der Tests (`tests/fake_bank.py`). Dazu kommen
HTTPS, ein gespeicherter Zustand, Befehle für die Kommandozeile, eine
Weboberfläche (`/admin`, Block E13) und ein Generator für erfundene
camt.053-Dateien (`tests/camt_generator.py`).

**Nur Testdaten, nur für den Entwicklungsrechner:**

- Der Server lauscht nur auf `127.0.0.1`; eine andere Adresse lässt sich
  nicht einstellen.
- Keine echten Schlüssel, Kontonummern oder Auszüge verwenden.
- `tools/` gehört nicht zum installierten Modul (in `setup.py` und
  `MANIFEST.in` ausgeschlossen).

## Voraussetzungen

- Das Modul ist editierbar installiert (`pip install -e ./account_ebics`
  in `~/python/trytond`); der Server nutzt dessen Protokollschicht.
- Nur Python-Standard und die vorhandenen Pakete `cryptography` und `lxml`
  (für `demo` zusätzlich `requests`); es wird nichts installiert.

Alle Befehle werden mit dem Python der Tryton-Umgebung aufgerufen, im
Modulverzeichnis `~/python/trytond/account_ebics`:

```bash
../.venv/bin/python tools/ebics_testserver.py <Befehl> [Optionen]
../.venv/bin/python tools/ebics_testserver.py <Befehl> --help
```

## Eckdaten

| Angabe | Wert |
|---|---|
| URL | `https://127.0.0.1:8443/ebics` (Port mit `--port` änderbar) |
| Weboberfläche | `https://127.0.0.1:8443/admin#token=…` (vollständige URL in der Startausgabe von `serve`) |
| Host-ID | `TESTBANK` |
| Zustandsverzeichnis | `~/python/ebics_testserver_state/` (`--state-dir` oder Umgebungsvariable `EBICS_TESTSERVER_STATE`) |
| TLS-Zertifikat (`ca_bundle`) | `<Zustandsverzeichnis>/server-cert.pem` |
| Passphrase des Bank-Keyrings | `testserver` (fest, nur Testdaten) |

`localhost` funktioniert auch, kann aber zuerst auf `::1` auflösen. Der
Server lauscht nur auf IPv4, deshalb besser `127.0.0.1` verwenden.

## Zustandsverzeichnis

| Datei / Verzeichnis | Inhalt |
|---|---|
| `bank-keyring.zip` | Bankschlüssel A006, X002, E002 als Container nach Spezifikation Kap. 8.1, Passphrase `testserver` |
| `server-cert.pem`, `server-key.pem` | TLS-Zertifikat (selbstsigniert für `localhost` und `127.0.0.1`) und Schlüssel des Servers |
| `bank.json` | Host-ID, Hashwerte der Bankzertifikate, Zähler, Segmentgröße, eingeschaltete Fehlerfälle |
| `participants.json` | Teilnehmer (Partner-ID, User-ID) mit Zustand, Zertifikaten aus INI/HIA und `SecurityMedium` |
| `transactions.json` | Download-Transaktionen (Segmente, Dateien, BTF, Zeitraum) und Quittungen |
| `downloads/<BTF>/` | bereitgestellte Dateien, z. B. `downloads/EOP_DE_camt.053_ZIP/`, mit `files.json` (BTF, Datum) |
| `delivered/<BTF>/` | nach positiver Quittung hierher verschoben |
| `messages/` | jede Anfrage und Antwort als `<Zeitpunkt>-<Auftragsart>-request.xml` / `-response.xml`; dazu der Klartext der Auftragsdaten als `-orderdata.xml` (INI, HIA entpackt; HPB Bankschlüssel) bzw. `-orderdata.zip` (BTD-Container) |
| `state.lock` | Dateisperre für Server und Befehle |

Server und Befehle ändern den Zustand nur unter der Sperre. Der Server
liest den Zustand vor jeder Anfrage neu; Befehle in einem zweiten Terminal
wirken deshalb sofort, und nach einem Neustart geht es nahtlos weiter.

Dateien nur mit `add-file` oder `make-camt053` bereitstellen. Eine Datei,
die man von Hand nach `downloads/` kopiert, kennt der Server nicht, weil
sie nicht in `files.json` steht.

## Befehle

| Befehl | Wirkung |
|---|---|
| `serve [--port 8443] [--auto-release] [--xsd-dir DIR] [--no-admin]` | Server starten. Beim ersten Start werden Bankschlüssel und TLS-Zertifikat erzeugt. Mit `--xsd-dir` (oder `EBICS_XSD_DIR`) werden eingehende Requests gegen die Schemas H005 geprüft und Abweichungen angezeigt. `--no-admin` schaltet die Weboberfläche ab. |
| `status` | Teilnehmer mit Zustand, Hashwerte X002/E002 der Bank, Dateien je BTF (bereitgestellt / ausgeliefert), offene Transaktionen, Fehlerfälle, Pfad des TLS-Zertifikats |
| `release <partner_id> <user_id>` | Freigabe nach „Prüfung der Briefe“ (auch: Sperre aufheben) |
| `suspend <partner_id> <user_id>` | Teilnehmer sperren: HPB und BTD antworten `091004` |
| `add-file <btf> <datei> [--date JJJJ-MM-TT] [--name NAME]` | Datei für BTD bereitstellen |
| `make-camt053 --iban IBAN [--date JJJJ-MM-TT] [--entries 5] [--currency EUR] [--start-balance 1000.00]` | erfundene camt.053.001.08 erzeugen und unter `EOP/DE/camt.053/ZIP` bereitstellen |
| `fault <name> [<wert>]`, `fault --clear`, `fault` | Fehlerfall ein- oder ausschalten, alle löschen bzw. anzeigen |
| `demo [--port 8443] [--negative]` | Selbsttest ohne Tryton gegen den laufenden Server: HEV → INI → HIA → (Freigabe) → HPB → BTD → Quittung |
| `reset [--yes]` | Zustand löschen; das TLS-Zertifikat bleibt, damit `ca_bundle` gültig bleibt |

### BTF-Angabe bei `add-file`

Die BTF-Angabe hat die Reihenfolge von D15 (Service Name / Scope / Option /
Message / Version / Container). Beispiele:

- Kurzform ohne leere Teile: `EOP/DE/camt.053/ZIP`,
  `STM/DE/camt.052/ZIP`, `SDD/DE/COR/pain.008/08/XML`
- Langform mit sechs Teilen und `-` für leere Teile:
  `SDD/-/COR/pain.008/-/XML`

Steht zwischen Service Name und Message nur ein Teil mit drei Zeichen
(z. B. `EOP/COR/camt.053`), ist unklar, ob Scope oder Option gemeint ist.
In diesem Fall die Langform verwenden.

### Auswahl der Dateien bei BTD

- Alle BTF-Teile müssen übereinstimmen; ein fehlender Teil passt nur zu
  einem fehlenden Teil. Ausnahme ist die Version: Sie schließt nur aus,
  wenn Datei und Anfrage verschiedene Versionen angeben.
- Ohne `DateRange` liefert der Server alle noch nicht quittierten Dateien.
- Mit `DateRange` liefert er alle Dateien mit Datum im Zeitraum (inklusive),
  auch bereits ausgelieferte.
- Gibt es keine passende Datei, antwortet er `090005`.
- Eine positive Quittung verschiebt die gelieferten Dateien nach
  `delivered/`; nach einer negativen bleiben sie bereitgestellt.

### Fehlerfälle

| Name | Wert | Wirkung |
|---|---|---|
| `BTD` | technischer Code, z. B. `091008` | Antwort der BTD-Initialisierung mit diesem Code |
| `HPB` | technischer Code, z. B. `091002` | Antwort auf HPB mit diesem Code |
| `HPB_wrong_key`, `BTD_wrong_key` | – | Auftragsdaten für einen fremden Schlüssel verschlüsselt |
| `HPB_garbage` | – | Auftragsdaten nicht entpackbar |
| `BTD_tamper` | – | Antwort nach der Signatur verändert (Signaturfehler) |
| `BTD_endless` | – | `lastSegment` nie `true` |
| `BTD_num_segments` | Zahl | angekündigte Anzahl Segmente |
| `BTD_fewer` | – | kündigt ein Segment mehr an, als gesendet wird |
| `short_transaction_key`, `full_transaction_key` | – | TransactionKey gekürzt bzw. auf volle Länge aufgefüllt |

Beispiel: `fault BTD 091008`, ausschalten mit `fault BTD_tamper false`
oder `fault --clear`.

Ein Request, den der Server nicht lesen kann oder nicht kennt, erhält
`061002 EBICS_INVALID_REQUEST`.

## Weboberfläche

`serve` stellt unter demselben Port die Seite `/admin` bereit. Die
Startausgabe zeigt die vollständige URL mit dem Zugangstoken, z. B.

```text
EBICS-Testserver (nur Testdaten)
  URL:          https://127.0.0.1:8443/ebics
  Weboberfläche: https://127.0.0.1:8443/admin#token=Xy…
```

Diese URL im Browser öffnen (am besten kopieren). Das Token wird bei
jedem Start neu erzeugt und steht nur im Speicher und in dieser Ausgabe;
nach einem Neustart gilt die alte URL nicht mehr. Der Teil nach `#` wird
vom Browser nicht an den Server geschickt; die Seite liest ihn und sendet
das Token im Kopf `X-Testserver-Token` mit jedem Aufruf der Schnittstelle.

Aufbau der Seite:

- **links** die Nachrichtenliste, neueste oben, Aktualisierung alle
  2 Sekunden: Auftragsart, Phase, Zeit, Teilnehmer, technischer und
  fachlicher Rückgabecode. Farben: grün OK, blau Information bzw. keine
  Daten (`011000`, `090005`), orange Teilnehmerzustand (`091002`),
  rot Fehler.
- **rechts** nach Klick auf eine Nachricht Anfrage und Antwort, darunter
  die Auftragsdaten im Klartext: bei INI/HIA die entpackten Schlüssel mit
  Hashwerten der Zertifikate, bei HPB die Bankschlüssel mit Hashwerten
  (wie `status`), bei BTD die Dateien des ZIP-Containers mit dem Inhalt der
  XML-Dateien.
  - Ohne Häkchen ist das XML mit dem zentralen Parser eingerückt; lange
    Base64-Werte sind gekürzt („… [n Zeichen gekürzt]“).
  - „roh“ zeigt die Dateien unverändert, „Base64 vollständig“ das
    eingerückte XML ohne Kürzung.
  - „neueste automatisch anzeigen“ springt bei jeder neuen Nachricht auf
    diese.
- **unten** Buttons für `status`, `release` und `suspend` (Teilnehmer aus
  der Auswahlliste), `make-camt053` (IBAN, Anzahl Buchungen), `fault`
  (Fehlerfall, Wert) und `fault --clear`, `demo` (optional `--negative`),
  `reset` (mit Rückfrage), dazu ein Eingabefeld für beliebige Befehle
  (wie auf der Kommandozeile, ohne Programmnamen, z. B.
  `add-file EOP/DE/camt.053/ZIP /pfad/datei.xml`) und das Ausgabefeld mit
  Exit-Code.

Regeln für Befehle über die Seite:

- Es laufen dieselben Befehle wie auf der Kommandozeile, nacheinander
  (ein zweiter Klick wartet).
- `serve` und `--state-dir` sind über die Seite nicht möglich; `reset`
  nur nach der Rückfrage der Seite (sie sendet `reset --yes`).
- `demo` läuft immer gegen den Server, der die Seite ausliefert (`--port`
  wird ersetzt).
- Pfade bei `add-file` sind Pfade auf dem Rechner des Servers.

Schutz: Die Seite ist nur über `127.0.0.1` erreichbar. Ohne gültiges Token
antwortet die Schnittstelle mit 403, ebenso bei einem anderen `Host`-Kopf
als `127.0.0.1:<Port>` oder `localhost:<Port>`. Inhalte der Nachrichten
werden nur als Text angezeigt, nie als HTML. Mit `serve --no-admin` ist
`/admin` abgeschaltet (404); `/ebics` bleibt unverändert.

### Zertifikat im Browser

Der Server hat ein selbstsigniertes Zertifikat; der Browser warnt beim
ersten Aufruf. Zwei Wege:

1. **Einmal bestätigen:** In Safari „Details einblenden“ → „diese Website
   besuchen“; in Chrome „Erweitert“ → „Weiter zu 127.0.0.1 (unsicher)“;
   in Firefox „Erweitert“ → „Risiko akzeptieren und fortfahren“.
2. **Dem Zertifikat vertrauen (macOS):** `server-cert.pem` aus dem
   Zustandsverzeichnis in der Schlüsselbundverwaltung öffnen:

   ```bash
   open ~/python/ebics_testserver_state/server-cert.pem
   ```

   Das Zertifikat landet im Schlüsselbund „Anmeldung“. Doppelklick auf
   „localhost“ → „Vertrauen“ → „SSL (Secure Sockets Layer)“: „Immer
   vertrauen“, Fenster schließen und mit dem Passwort bestätigen. Safari
   und Chrome nutzen den Schlüsselbund; Firefox hat eine eigene
   Zertifikatsverwaltung (Weg 1).

   Nach dem Test das Vertrauen wieder entfernen (Zertifikat
   „localhost / EBICS-Testserver (Testdaten)“ im Schlüsselbund löschen).
   `reset` behält das Zertifikat; nur wenn `server-cert.pem` gelöscht
   wird, entsteht ein neues, dem erneut vertraut werden muss.

Die Prüfung des Zertifikats in Tryton und in `demo` bleibt davon
unberührt (`ca_bundle`).

## Einstellung in `trytond.conf`

Tryton prüft das TLS-Zertifikat immer; der Testserver ist ihm nur über
`ca_bundle` bekannt (Spezifikation Kap. 8.2). Den absoluten Pfad
eintragen (`~` wird nicht aufgelöst):

```ini
[account_ebics]
ca_bundle = /Users/<name>/python/ebics_testserver_state/server-cert.pem
```

Am EBICS-Zugang in Tryton (ab E06):

- URL `https://127.0.0.1:8443/ebics`
- Host-ID `TESTBANK`
- Partner-ID und User-ID frei wählbar, z. B. `TESTPART` / `TESTUSER`

Die Hashwerte für „Bankschlüssel bestätigen“ zeigt `status`.

Hinweis: Tryton liest `ca_bundle` erst ab Block E06 (Verbindung). Bis
dahin prüft der Befehl `demo` den Ablauf ohne Tryton.

## Ablauf mit zwei Terminals (Test T9)

Terminal 1 – Server:

```bash
cd ~/python/trytond/account_ebics
../.venv/bin/python tools/ebics_testserver.py serve
```

Terminal 2 – Befehle:

```bash
cd ~/python/trytond/account_ebics
T="../.venv/bin/python tools/ebics_testserver.py"

$T make-camt053 --iban DE14123456780000004711 --entries 5
$T status
$T demo
$T status
ls ~/python/ebics_testserver_state/messages/
```

Freigabe von Hand für einen eigenen Teilnehmer (z. B. aus Tryton): nach INI
und HIA antwortet HPB mit `091002`. Dann folgt in Terminal 2

```bash
$T release TESTPART TESTUSER
```

und HPB liefert die Bankschlüssel. `demo` gibt den Demo-Teilnehmer
`DEMOPART`/`DEMOUSER` selbst frei.

Hinweise:

- `demo` legt bei jedem Lauf den Teilnehmer `DEMOPART`/`DEMOUSER` neu an.
- Ist keine Datei unter `EOP/DE/camt.053/ZIP` bereitgestellt, erzeugt
  `demo` selbst eine.
- `demo` quittiert positiv und verbraucht damit die bereitgestellten
  Dateien. Mit `demo --negative` bleiben sie für Tryton liegen.
- Beenden des Servers mit Strg+C; der Zustand bleibt erhalten.
- `reset` erzeugt beim nächsten Start neue Bankschlüssel. In Tryton dann
  HPB wiederholen und die Bankschlüssel neu bestätigen.

## Tests

Die automatischen Tests stehen in `tests/test_testserver.py` (E12 T1–T8,
Weboberfläche E13 T1–T6 in `AdminTestCase`). Sie starten den Server im
Testprozess auf einem zufälligen Port an `127.0.0.1` mit einem temporären
Zustandsverzeichnis. Ein Test (T5) importiert eine
erzeugte camt.053 über `account_statement_sepa` (`tests/test_module.py`).
