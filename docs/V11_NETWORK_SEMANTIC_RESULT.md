# V11 – funktionaler Netzwerkvertrag und aktuelle Nachweisgrenze

Basis: `32adfe8677c2eeecd8c2a5c62d5fed2350194a9d`, 01.10.2026.
Delta auf `security/codex-privileged-ops-2026-09-27`.
Keine Live-Aktivierung, kein sudo, kein Watchdog, kein PR.

## Governance und Fortsetzung

Die vom Benutzer ausdrücklich freigegebene lokale AGENTS-Korrektur entfernt
Mikrofreigaben und pauschale Stopps bei sicher behebbaren Vorbereitungsfehlern.
Der Mac-Preflight meldet `GOVERNANCE_V1_1_ACTIVE`. Die kanonische Governance
und historische Dokumente wurden nicht geändert.

Lokale Sicherung: `AGENTS.md.backup-20261001T034615Z` neben der Projektdatei.
Vorher SHA-256: `45f48196a8060c1b79f3a9d5b570ee63b7b17c22e19db7370d53e2bf6eda17bb`.
Nachher SHA-256: `bcd463aabeee8017883b4d13b567977a7ce7c410496ecb1da12c8aec8d4d5dda`.
Diff und Änderungsmanifest tragen denselben Zeitstempel. Dateimodus 0444 erhalten;
Sicherung und Änderungsnachweise 0600. Keine synchronisierten Quellen geändert.

## Gezielt belegte Verbraucher

| Verbraucher | Nachweis / Verwendung |
| --- | --- |
| Nginx `api.mychatbuddy.dev` | Zwei aktive Proxyziele `http://127.0.0.1:8081`; SHA-256 `0abd82507e6cfa45aacdd5b36c13ad9e1e8b187dde6187369af4030607456499` |
| `agent_offline.sh` | Host-Healthcheck über localhost:8081; SHA-256 `cf9b95efbd0a05b897d55adfa19b83113e3ffe11e99f5128b1e3a7571e7be874` |
| `watch_mommyramona.sh` | Proxy-Healthroute und Containername; SHA-256 `a775be3ac87af2869d60d06e8f164a5c8dad9890eaa610570f1aa7d684068d3b` |
| Prometheus-Konfiguration | Keine der gezielt gesuchten IP-/MAC-/Namens-/8081-Referenzen; SHA-256 `ff3940abd0647a579eb804e7bd60eebafe4d5a59f64aeec4910649a90f48f903` |
| Git-Sync / verschlüsseltes Backup | Referenzen auf das Anwendungs-Verzeichnis, kein belegter direkter IP-/MAC-Verbraucher |
| Docker | Publish 8081→8080, beide bisherigen Netzwerke; dynamisches IPAM |
| Aktuelle Route | Default via 172.25.0.1 über `tausendunde1nz_net`; zusätzlich direktes Compose-Netz |

Die Suche war auf bekannte aktuelle Konfigurationen und direkte Dateien in den
benannten Unit-, Cron-, Proxy- und Skriptverzeichnissen begrenzt. Keine neue
breite Inventur oder historische Akteurssuche. Keine Bot-/Provideraufrufe.

Mommyramona unverändert: ID
`e2473c1d0a106b515eee5e63984260046beae22b16724af281368f32c7bd69c7`,
Start 2025-11-01T12:31:14.600380348Z, RestartCount 0, Image
`sha256:f0c7c619b45ffb475d79c2339fbef21ced03c6e83d919d321ef89b40cd4889db`.

## Semantischer Vertrag

`network_contract_v11.py` ersetzt für neue Prüfungen die Annahme, dass jede
Endpoint-ID, Sandbox-ID, MAC und dynamische IP bytegleich zurückkehren müsse.
Der alte Experimentcode und seine Ergebnisse bleiben historische Nachweise.

Verbindlich sind Name, Image, Konfiguration (einschließlich gehashter Env-Werte),
HostConfig/Ports, Mounts, Netzwerk-IDs, DNS-Aliasse, IPAM-Vertrag, DriverOptions,
Gateway-Priorität und Default-Netz. Alias-Duplikate sind semantisch gleich;
zusätzliche Aliasse sind Fehler. Dynamisches IPAM wird nicht still statisch.
IP-/MAC-Pins dürfen nur auf Grundlage nachgewiesener Verbraucher gesetzt werden.
Unvollständige Verbraucherprüfung oder ungeklärte DNAT-Urheberschaft verweigert
Fall A. Unbekannte Befunde werden nicht als Abwesenheit gewertet.

Die Non-Root-Kandidatenprojektion ändert ausschließlich User 20001:20001,
CapDrop ALL, NNP, Rootfs read-only und den bestehenden Code-Bind auf read-only.
Sie weist unerwartete Basisprivilegien oder Mounts zurück. Ergänzend sind echte
UID-/Capability-/NNP-, DNS-, Hostport-, Proxy-, Monitoring-, Listener- und
MyChatBuddy-Prüfungen zwingend; ein Strukturvergleich ersetzt diese nicht.
Dies ist ein Prüfmodul, **keine fertig implementierte Host-Transaktion**.

## Isolierter Nachweis

Sechs reale Docker-Testfälle bestanden, nur UUID-benannte Testnetze und eigene
Testcontainer, festes vorhandenes Image, keine Host-Mounts, Non-Root,
Capabilities leer, NNP, read-only Rootfs, 128 MiB, 0,5 CPU, 64 PIDs.
Der einzige Test-Hostport wurde dynamisch und ausschließlich an 127.0.0.1
gebunden. Kein produktiver Port oder Netzwerkendpoint wurde verwendet.
Docker erzeugte und entfernte seine eigenen Testnetz-/Portregeln; es wurde keine
vorhandene produktive Firewallregel bearbeitet.

1. Baseline: DNS, Alias, Hostport→8080 und Default-Route erfolgreich.
2. Alter IP-Verbraucher fällt bei gezielt belegter Altadresse tatsächlich aus.
3. Recreate mit unverändert dynamischem IPAM bei konkurrierender Vergabe:
   neue IP **und** MAC; derselbe Hostport, Alias und DNS-Verbraucher funktionieren.
4. Statische Adresse bei belegtem Ziel: Docker verweigert mit HTTP 403 und
   `Address already in use`; andere 403-/500-Fehler gelten nicht als Nachweis.
5. Rollback nach fehlendem sekundärem Netz stellt den funktionalen Vertrag her.
6. Rollback nach fehlgeschlagenem Healthcheck stellt ihn ebenfalls her.

Das beweist die automatische Anpassung der Docker-Hostportweiterleitung im
Test. Es ist **kein direkter Kernel-DNAT-Kettenauszug** und ersetzt nicht die
Zuordnung der aktuellen produktiven Regel im Root-Preflight.
Alle Testressourcen entfernt; produktive Containerlisten einschließlich IDs,
Images, Mounts, Ports und Netzwerken vor/nach dem erfolgreichen Lauf identisch.

Frühe Testläufe bleiben getrennt erhalten. Selbstständig korrigierte
Harnessfehler: gemeinsamer Hostname verdeckte Service-DNS durch /etc/hosts;
zu langer Name überschritt Linux-Hostnamegrenze; Docker liefert für die echte
Adresskollision 403 statt des zunächst erwarteten Statusbereichs. Zusätzliche
Regressionstests decken diese Ursachen ab. Ein anfänglicher Listenvergleich
berücksichtigte Port-/Mount-Reihenfolgen fälschlich als Drift; die kanonische
Wiederholung bestätigt unveränderte produktive Konfigurationen. Keine
Sicherheitsentscheidung oder Zugriffsprüfung wurde abgeschwächt.

Nachweise privat:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v11-semantic-20261001/`.
Die JSON-Begleitdatei bindet Ergebnisse, Quellhash und sämtliche Versuchlogs.
Private Rohdaten und Sicherungen werden nicht committed.

## Tatsächlich verbleibende Beweisgrenze

- `/opt/n8n/data/database.sqlite`: 1000:1000, 0600, für chatops nicht lesbar.
  Aktive Workflow-Ziele sind daher nicht vollständig ausgeschlossen.
- `/etc/nginx/sites-enabled/tu1nz.conf`: root:root, 0600; weitere wenige bekannte
  geschützte Skripte müssen zielgerichtet geprüft werden.
- Das unveränderte alte `nat.json` belegt 8081→172.25.0.2:8080, aber speichert
  keine Chain. SHA-256
  `42a4b7bb4af6061dfe0d50a4e133e10b6891cebd1fffdee70c6951ec52b42964`,
  gebunden durch Manifest
  `a5c32ce09af5bdb53495bae7dbe3694daf6069824c691a3c2152723686949be2`.
  Aus diesem Beleg allein wird keine Docker-Urheberschaft behauptet.

Daher: `NETWORK_CONSUMERS_AND_NAT_CHAIN_PENDING`, nicht ein MAC-/IPAM-Blocker
und nicht die historische V9-Beweisgrenze. Weder Fall A noch ein statischer
Fall-B-Vertrag sind vollständig freigeprüft. Keine statische IP aus Vermutung.

`network_evidence_v11.py` bereitet ausschließlich diese engen Restlesevorgänge
für den späteren **einen** V11-Root-Lauf vor. Keine CLI oder separate sudo-
Anforderung. Es liest feste Pfade und `iptables-save -t nat`, gibt ausschließlich
Referenzklassen/Metadaten/Hashes aus und prüft genau die DOCKER-DNAT-Zuordnung.
SQLite wird niemals auf der produktiven Datenbank geöffnet: DB/WAL werden
konsistent in ein leeres, geschütztes V11-Nachweisverzeichnis kopiert, nur dort
mit festen SELECTs geprüft und anschließend entfernt. Drift, fehlende Daten,
Parserfehler oder zusätzliche Regeln führen zur Verweigerung.

Vor einer Mutation muss dieses Ergebnis mit dem lesbaren Verbraucherbefund
zusammengeführt werden. Der vorbereitete AppArmor-Leser bleibt separat
unverändert; fehlender menschenlesbarer Policy-Export ist kein neues Gate.
Es gab keinen privilegierten Leselauf und keinen Zugriff über Docker als Umweg
um die Dateirechte. Kein Aktivierungslauncher wird als fertig dargestellt.
Die vollständige V11-Host-Engine/Broker-/Writer-Integration ist noch nicht fertig;
entsprechend wird jetzt keine MacBook-Bereitschaft und kein sudo angefordert.

## Validierung

32 neue Offline-Tests lokal bestanden; zusammen mit bestehenden V11-Tests
70/70 auf dem Server. Insgesamt 452 zusätzliche gezielte Tests bestanden
(V11 70, V9 130, V10 56, Privilege 124, Root-Trust 64, Broker 8).
Der vollständige bestehende Workflow besteht mit **108/108 Schritten**.
Zwei ausdrücklich optionale Anwendungstests in Schritt 100 sind wegen des
fehlenden gepaarten Application-Checkouts übersprungen, nicht als bestanden
gezählt. Alle Läufe in einer neuen isolierten Kopie unter Umask 0022.

Workflow: `d0420d6cd0fa6fee7113ed9283ef5970c4aa58a2f40d8dc0ca3fec3fdc1214f4`.
Ergebnis: `aa64a65667e7f95b24e1259f556075dd7236df63a084386eaabb6cce859b6e78`.
Privat: `v11-semantic-workflow-20261001T040404Z-5133af8c` unter dem bisherigen
privaten Nachweispfad. Keine neuen Quellen in den historischen Prüfmanifesten.

701 Bestandsdateien, 42 Hardening-Dateien, 30 V9-Quellen und 1125 historische
Nachweisdateien bytegleich. `1cf0d79` bleibt Vorfahr. Detached Checkout sauber
und unverändert bei `9b383960291da469671c3888cfa4fdcc3c33cf01`.
Die ursprünglichen V11-Netzwerkexperimente sowie AppArmor-Quellen bleiben
unverändert. Die nächste Live-Zulassung bleibt bis zum nachgewiesenen
funktionalen Verbraucher-/NAT-Vertrag und zur vollständigen V11-Integration
verweigert; hier wird weder Aktivierungsreife noch ein fertiger Launcher behauptet.
