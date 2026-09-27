# Lesende Abhängigkeitsanalyse: zusätzliches Bot-Netzwerk, 2026-09-27

**Entscheidung: Zweck weiterhin ungeklärt — keine Aktivierung und keine Entfernung.**
Die Analyse ist bis auf ausdrücklich benannte Zugriffslücken durchgeführt; sie ist kein
Nachweis, dass der Anschluss entbehrlich wäre. Der Container bleibt unverändert im bekannten
Docker-Status unhealthy wegen des internen Healthchecks auf 8090 statt 8080.

## Kommunikationsmatrix und Beweisstärke

| Quelle | Ziel / Weg | Beleg und Einschränkung |
|---|---|---|
| Host-Nginx / eingehende Webhooks | Host 8090 → spicymila:8080 | Portbindung und aktive Proxykonfiguration; `/spicy/` und `/spicymila/`-Routen. Keine Webhooks ausgelöst. |
| Host-Nginx / eingehende Webhooks | Host 8081 → mommyramona:8080 | Portbindung und Proxykonfiguration; `/mommyramona/`-Routen. Konkretes aktuelles DNAT-Ziel noch im privilegierten Sammler vorgesehen. |
| spicymila | Default über eth0, 172.21.0.1, spicymila_bot_default | Direkt aus /proc/net/route; sekundäres eth1 für 172.25.0.0/16. |
| mommyramona | Default über eth0, 172.25.0.1, tausendunde1nz_net | Direkt aus /proc/net/route; eth1 für 172.20.0.0/16. Netz hat für diesen Peer eine tatsächliche Routingfunktion. |
| spicymila ↔ mommyramona | Gemeinsames 172.25.0.0/16 | Technisch durch beide Endpoints möglich; keine direkte Verbindung im Beobachtungsfenster, keine entsprechende Code-/Umgebungsreferenz gefunden. Bedarf nicht bewiesen. |
| spicymila | api.telegram.org und openrouter.ai, HTTPS | Ziel-Hosts aus laufendem/Host-Anwendungscode; keine künstlichen Requests. Kein tatsächlicher Provider-Verkehr im Socket-Fenster erfasst. |
| mommyramona | api.telegram.org, HTTPS | Aktueller Anwendungscode. Alte main.py-Sicherungen nennen auch api.mychatbuddy.dev und openrouter.ai; historische Dateien sind kein Beweis aktueller Ausführung. |
| n8n aktuell | eigenes n8n_n8n_default, Host-Proxy 127.0.0.1:5678 | Kein aktueller Anschluss an tausendunde1nz_net. Persistierte Workflow-Datenbank wurde nicht als vollständig geprüfte Abhängigkeitsquelle ausgewertet. |
| n8n historisch | tausendunde1nz_net, 172.25.0.4 | Existierender Inspect-Snapshot aus analysis/n8n_fix_2026-03-18, identische Netzwerk-ID. Historischer Mehrzweckgebrauch belegt, konkreter Bot-Workflow nicht. |
| Prometheus | cAdvisor 172.29.0.2:8080 | Im gesamten Beobachtungsfenster etablierte TCP-Verbindung aus 172.29.0.4; monitoring_default. |
| Prometheus | Host-Gateway 172.29.0.1:9100 | Etablierte TCP-Verbindung zu Node Exporter, der Host-Netzwerk verwendet. Kein Bot-Gemeinschaftsnetz erforderlich für diesen belegten Pfad. |
| Grafana | monitoring_default | Socket-Inventur vorhanden; kein Anschluss an Bot-Netze. |
| api-mychatbuddy | proxy, 172.19.0.2, intern :8000 | Listener und lokale Health-TIME_WAIT-Sockets gesehen; kein gemeinsames Bot-Netz. |
| Alte Bot-Wächter | öffentliche API-Healthroute, bei Fehler docker restart | Skripte vorhanden, aber zugehörige /etc/cron.d-Dateien enthalten keine aktiven Wächter-Einträge. Root-Crontab noch ungelesen; keine globale Deaktivierungsbehauptung. |
| Backup/Git-Sync | Bot-Verzeichnisse | Dateisystemreferenzen in bestehenden Backup-/Sync-Skripten und Unit; kein gefundener gemeinsamer Netzwerkbezug. |

## Containerinventur

Alle Netzwerke, vollständigen Endpoint-Einstellungen, IPv4-/IPv6-Routen, hosts- und
resolv.conf-Inhalte wurden lesend erfasst. Die folgende Tabelle fasst die Inventur zusammen.
Node Exporter teilt den Host-Netzwerk-Namespace; seine Socket-Tabelle enthält daher auch
fremde Host-Dienste und darf nicht vollständig dem Exporter zugeschrieben werden.

| Container | Netzwerke / IPv4 | Erfasste TCP-Listenerports | Default-Route |
|---|---|---|---|
| spicymila_bot | spicymila_bot_default: 172.21.0.2, tausendunde1nz_net: 172.25.0.3 | 8080 | eth0 via 172.21.0.1 |
| n8n | n8n_n8n_default: 172.26.0.2 | 5678 | eth0 via 172.26.0.1 |
| tu1nz_grafana | monitoring_default: 172.29.0.3 | 3000 | eth0 via 172.29.0.1 |
| tu1nz_node_exporter | host: (Host) | 53, 80, 443, 2222, 3000, 5432, 5678, 8080, 8081, 8090, 8095, 8096, 8125, 9090, 9100, 18096, 18110, 19999, 37138, 41095 | eth0 via 172.31.1.1 |
| tu1nz_cadvisor | monitoring_default: 172.29.0.2 | 8080 | eth0 via 172.29.0.1 |
| tu1nz_prometheus | monitoring_default: 172.29.0.4 | 9090 | eth0 via 172.29.0.1 |
| jellyfin | homeserver_net: 172.23.0.2 | nicht im passiven Umfang | eth0 via 172.23.0.1 |
| telegram_bot_mommyramona | tausendunde1nz_net: 172.25.0.2, telegram_chatbot_default: 172.20.0.2 | 8080 | eth0 via 172.25.0.1 |
| api-mychatbuddy | proxy: 172.19.0.2 | 8000 | eth0 via 172.19.0.1 |

## DNS und Endpoint-Identität

Beide Bots verwenden den eingebetteten Docker-Resolver 127.0.0.11 und den konfigurierten
Tailnet-Suchbereich. Docker Inspect enthält jeweils Containername und kurze Container-ID
als DNSNames; auf dem Gemeinschaftsnetz sind Aliases unverändert leer. Auf ihren eigenen
Compose-Netzen bestehen die doppelten Container-/Dienstnamen-Aliasse.
/etc/hosts enthält beide jeweiligen Container-IP-Adressen. Es wurden keine DNS-Testanfragen
erzeugt. Die tatsächliche Antwort einer frischen Namensauflösung ist daher **nicht** validiert;
Resolverkonfiguration und registrierte DNSNames sind gesichert. Vorhandene DNS-UDP-Sockets
waren sichtbar, konkrete DNS-Fragen/-Antworten wurden nicht aufgezeichnet.

Netzwerk-ID bleibt
`470c1e93874782eeea4d9060f0502efdc6911d7afd96171c147e13a7013cd646`;
Spicymila 172.25.0.3, Mommyramona 172.25.0.2. Treiber bridge, IPv4-Subnetz
172.25.0.0/16, Gateway172.25.0.1, keine IPv6-Adresse. Keine Endpoint-Einstellung wurde geändert.
Zusätzliche Compose-Aliasse werden weiterhin nicht als gleichwertig akzeptiert.

## Historie, Betriebsdateien und Protokolle

- Beide Application-Repositories und alle lokal vorhandenen Refs wurden mit Git-Pickaxe auf
  Netzwerkname, beide gemeinsamen IPs und `docker network connect` untersucht: kein Treffer.
  Spicymila-Remote-Refs waren lesbar und sämtliche Tipps lokal vorhanden. Mommyramona-Remote
  war nicht lesbar; eine vollständige Remote-Historie wird ausdrücklich nicht behauptet.
- Control: 97 lokale Refs untersucht; nur neue Untersuchungs-/Recoverydokumente tauchen in
  der versionierten Pickaxe-Suche auf. Die Remote-Liste enthält 243 Head-/Tag-Zeilen;
  aktuelles control-main und ein weiterer Branch/Tag sind lokal noch nicht vorhanden.
  Kein Fetch und keine Git-Referenzänderung am detached Checkout.
- Zusätzlich unversionierte/ignorierte vorhandene Betriebsnachweise gelesen. Dabei wurde
  der alte n8n-Inspect mit 172.25.0.4 auf exakt demselben Netzwerk gefunden. Der damalige
  n8n-Container war am 2025-11-13 erstellt worden. Das belegt nicht den Zeitpunkt oder
  Urheber des manuellen Bot-Anschlusses.
- Lesbare Deploymentskripte, /etc/systemd/system, Hersteller-Units, /usr/local/bin,
  /etc/cron*, Proxykonfigurationen und aktuelle Benutzer-Crontab geprüft. Keine passende
  manuelle Netzwerkverbindungsanweisung gefunden. Geschützte Dateien bleiben als Lücke erfasst.
- Docker-Journal: 895 lesbare Einträge; frühester Eintrag März2026, also keine Abdeckung
  der Netzwerkanlage im Oktober2025. Keine passenden Netzwerk-/Bot-Treffer. Die aktuelle
  Docker-Netzwerk-Ereignisabfrage lieferte keine Einträge; der Ereignisring ist kein Archiv.
- Bot-Logs: Spicymila 18 protokollierte GET /health mit200 seit letzter Neuerstellung;
  Mommyramona letzte20.000 Zeilen ausschließlich erkannte GET /health mit200,
  2026-08-29 bis2026-09-27, Quelladresse172.25.0.1. Spicymila-Logs enthalten Gateway172.21.0.1.
  Keine Bot-Nachrichten oder Log-Payloads gespeichert/ausgegeben.
- Vorhandene Nginx-Logs einschließlich gzip-Archive wurden bis höchstens100.000 Zeilen
  je Datei nach einer festen Liste bekannter Health-/Webhook-Routen ausgewertet.
  Gezählt wurden u.a.48.530 erfolgreiche Mommyramona-Healthzugriffe und1.399 erfolgreiche
  Spicymila-Healthzugriffe; historische502 sind separat gezählt. Keine Client-IPs,
  Querystrings, Requestbodies oder beliebigen Requestpfade ausgegeben. Diese aggregierten
  historischen Zähler beweisen keine aktuellen Webhook-Zugriffe oder Netzwerkanforderungen.

## Passive Beobachtung

186,074840873 monotone Sekunden;13 sequenzielle Stichproben ungefähr alle15 Sekunden,
8 relevante Container-Netzwerk-Namespaces. Gelesen wurden /proc/net/tcp,tcp6,udp,udp6.
Keine Paketerzeugung, Payload-Erfassung, Bot-Nachricht, Webhook oder externer Testrequest.
In beiden Bot-Namespaces wurden nur der 8080-Listener und Docker-DNS-Sockets erfasst;
keine Peer-Verbindung, kein etablierter ausgehender Bot-Socket in diesen Stichproben.
Prometheus-Verbindungen zu cAdvisor/Node Exporter wurden dagegen positiv erfasst.

Dies ist eine passive Socket-Stichprobe, **keine lückenlose Paket-/Flowaufzeichnung**.
Kurze oder seltene Verbindungen können fehlen. Die Methode begründet ausdrücklich keine
Entfernungsfreigabe. Zeit, Protokoll, lokale/entfernte Adresse und Port sowie Socketzustand
sind privat gespeichert; keine Payloads oder Prozessargumente. Listener ohne Prozesszuordnung
werden nicht als einem bestimmten Hostprozess zugeordnet dargestellt.

## Privilegierte Restprüfung — vorbereitet, nicht ausgeführt

Offen sind Root-Crontabs, einzelne geschützte Skripte/Proxydateien, ergänzende Cron-/Docker-
Journalmetadaten und der genaue DNAT-Pfad für8090/8081. Dafür wurde genau ein rein lesender
Sammler vorbereitet:
`scripts/tu1nz_spicymila_dependency_readonly.py`.
Er öffnet feste Pfade ausschließlich lesend, lehnt Symlinks beim Dateiöffnen ab, reduziert
Inhalte auf Prüfsumme, Rechte, Besitzer, Trefferbegriffe/-zeilen und gibt keine Inhalte aus.
Die einzigen externen Programme sind lesende journalctl- und iptables-save-Aufrufe.
Kein Capture, kein Dienststart, kein Neustart, keine Konfigurationsänderung, kein HTTP-Aufruf.

Selbsttests für Geheimnis-Unterdrückung, Kommentar-/Aktivzeilen und leere Eingaben bestanden;
Python-Syntax geprüft. Der privilegierte Hauptlauf wurde nicht gestartet.
Sammler-SHA256: `29ff4d5261e4f8fa3bcf0ac82a8763b02490bbe19dca402815a19accb3b6fd75`.
Später ein einziger sudo-Python-Aufruf mit vorherigem In-Memory-Hashvergleich und Ausführung
der exakt geprüften Bytes. Ausführung erst nach der neuen ausdrücklichen Bestätigung
„Ich bin am MacBook bereit.“; Passwort ausschließlich verdeckt im Terminal.

Weitere offene Evidenz: historischer Mommyramona-Remote, frühere n8n-Workflowabhängigkeiten,
fehlende Journalhistorie aus2025 und nicht aktiv getestete DNS-Auflösung. Auch eine erfolgreiche
privilegierte Restprüfung kann nicht automatisch alle historischen Lücken schließen.

## Entscheidung und Erhaltung

Erforderlichkeit von Spicymilas zusätzlichem Endpoint ist nicht bewiesen; Entbehrlichkeit
ist ebenfalls nicht bewiesen. Daher kein Recreate- oder Entfernungsplan als freigegebene
Aktivierung. Technischer Altbestand bleibt erhalten, Healthcheck-Fix bleibt getrennt zurückgestellt.
Der alte gepinnte Launcher wurde nicht geändert und bleibt ungültig. Kein PR, kein Merge.

Frischer Vergleich gegen die private Ausgangsinventur bestätigt identische Produktions-
Container-IDs, Image-IDs, Startzeiten, Restartzähler, Config, HostConfig, Mounts und Endpoints.
Compose-SHA256 unverändert
`04c65475baa7a55067366b78295c8fa663df7996beca04980e191dded7dc3da0`.
Alle42 Hardening-Dateien bytegleich, Integrationsstand1cf0d79 weiterhin Vorfahr;
detached Checkout7c634d3b82572e8459d51c69f04dce82c624d766 sauber und unverändert.

Nachweise (0700-Verzeichnis,0600-Dateien):
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/spicymila-dependencies-20260927T092726Z/`.
Inventur, Netzwerkdaten, Referenzen/Historie, Socket-Stichproben, Ereignisring,
Nginx-/Bot-Routenzähler, alte n8n-Netzwerkdaten, Ref-Abdeckung und Erhaltungsnachweis
liegen getrennt vor. Ein SHA256-Manifest bindet die Dateien. Keine Rohlogs oder
vollständigen Secret-Umgebungen werden committed.


## Nachtrag: privilegierter Sammellauf nach Bereitschaftsbestätigung

Daniel hat seine Bereitschaft bestätigt und das Passwort selbst verdeckt im Terminal
 eingegeben. Der gepinnte Sammler wurde einmal ausgeführt. Ergebnis: Exit-Code1,
stdout-Datei0 Bytes, SHA256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Statusdatei: `privileged-20260927T093928Z.json.status.json` im obigen Nachweisverzeichnis.

Die root-Journalabfrage wurde als laufender Prozess beobachtet; danach scheiterte der
Sammellauf innerhalb seines Zeitlimits. Wahrscheinliche Ursache ist der konfigurierte
120-Sekunden-Timeout. Stderr wurde nur im Terminal ausgegeben und nicht gesichert;
die genaue Exception ist deshalb **nicht abschließend nachgewiesen**.

Der Sammler erzeugt sein JSON erst nach allen Teilabfragen. Dadurch gingen bei diesem
Fehler auch die zuvor nur im Speicher gesammelten Datei-Metadaten verloren. Es liegt
kein verwertbarer privilegierter Prüfnachweis vor. Root-Crontab, geschützte Dateien und
DNAT-Prüfung bleiben offen; ihre erfolgreiche Prüfung wird nicht behauptet.
Keine zweite sudo-Ausführung oder erneute Passwortabfrage wurde gestartet.

Vor einer Wiederholung muss der Sammler separate, sofort gespeicherte Abschnittsergebnisse
und einen geschützten Fehlernachweis liefern. Die Journalabfrage muss gezielt filtern und
ihre Zeit-/Ergebnisgrenzen explizit ausweisen; ein Timeout darf die Datei- und NAT-Ergebnisse
nicht verlieren lassen. Der unveränderte Sammler soll nicht erneut ausgeführt werden.

Abschließender Vergleich nach dem Fehllauf bestätigt unveränderte Produktionskonfiguration,
Container-IDs, Startzeiten, Restartzähler, beide Bot-Endpoints und Compose-Prüfsumme.
Die42 Hardening-Dateien bleiben bytegleich; der detached Checkout ist unverändert und sauber.
Die Entscheidung bleibt **Zweck ungeklärt; keine Aktivierung und keine Entfernung**.
Der bekannte unhealthy-Status und der ungültige alte Aktivierungslauncher bleiben bestehen.
