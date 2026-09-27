# Ergebnis des freigegebenen lesenden v2-Laufs — 2026-09-27

Entscheidung: **Zweck der zusätzlichen Spicymila-Netzwerkverbindung weiterhin ungeklärt.**
Keine Aktivierung, keine Entfernung, keine Änderung an Endpoints, Compose oder Healthcheck.

## Ausführung und Integrität

Nach erneuter ausdrücklicher Bereitschaftsbestätigung wurde genau der vorbereitete
sudo-Befehl ausgeführt. Daniel gab das Passwort selbst verdeckt im Terminal ein.
Die geprüften Skriptbytes wurden nach In-Memory-SHA256-Prüfung ausgeführt:
`647b74d7fb5ec8d07f6dc0e0995ff24166d01a0bf1bf5b8fcc510b2cd92e7511`.
Ausgangscommit: `1ccaf6f15a87d2d82410294562ce0d8883e7ec46`.
Kein zweiter privilegierter Sammellauf wurde gestartet.

Ergebnis: Exitcode2, Manifest **INCOMPLETE**. Monotone Laufzeit418,535807401 Sekunden.
55 Abschnitte: Laufmetadaten, geschützte Dateien, Proxy,51 Journalfenster, NAT.
Das unveränderte Manifest verzeichnet6 OK und49 ERROR. Es bindet104 Ergebnis-/Fehlerdateien;
mit manifest.json sind105 Dateien vorhanden. Sämtliche Hashes, Größen und0600-Modi wurden
geprüft; Laufverzeichnis0700, Eigentümer chatops (UID1001), keine Fremddateien oder Symlinks.

Privater Nachweispfad:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/collector-v2-20260927T100814Z-437c36315a0d/`

Manifest-SHA256:
`a5c32ce09af5bdb53495bae7dbe3694daf6069824c691a3c2152723686949be2`.
Wrapperstatus und nachträgliche Auswertung liegen getrennt unter
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/collector-v2-validation-20260927T094954Z/`.
Die Originalergebnisse werden weder überschrieben noch nachträglich auf COMPLETE gesetzt.

## Verwertbare neue Befunde

- Geschützte Dateien:605 Metadatensätze, keine Abschnittsfehler.
- Proxy/Nginx:57 Metadatensätze, keine Abschnittsfehler. Quell-Symlinks sind bewusst
  als nicht verfolgt verzeichnet, nicht als inhaltlich geprüft dargestellt.
- Kein Treffer für tausendunde1nz_net,172.25.0.2,172.25.0.3 oder docker network connect
  in den tatsächlich gelesenen Dateien dieser beiden Abschnitte.
- Im inventarisierten Crontab-Verzeichnis sind chatops und eine chatops-Sicherung erfasst;
  kein root-Crontab-Dateieintrag. Beide chatops-Dateien enthalten keine der Suchreferenzen.
  Das ist eine Dateiinventur, kein Beweis für die Abwesenheit beliebiger externer Scheduler.
- Die geschützte Mommyramona-.env enthält keine der gesuchten Netzwerk-/Peer-/Portreferenzen.
  Keine Umgebungswerte wurden ausgegeben oder committed.
- NAT-Abschnitt erfolgreich, rc0, kein Timeout. Tatsächliche DNAT-Ziele:

| Hostport | Kernel-DNAT-Ziel | Netz |
|---|---|---|
|8090/tcp|172.21.0.2:8080|spicymila_bot_default|
|8081/tcp|172.25.0.2:8080|tausendunde1nz_net|

Damit ist der aktuell veröffentlichte Spicymila-Zugangsweg nicht auf seinen zusätzlichen
Endpoint172.25.0.3 angewiesen. Das beweist **nicht**, dass kein anderer seltener, historischer
oder noch ungeklärter Client diesen Endpoint benötigt. Mommyramona verwendet das gemeinsame
Netz dagegen sowohl als bereits belegte Default-Route als auch als Ziel des Host-DNAT.
Es gab keinen künstlichen Netzwerk-/Webhook-/Bot-Request zur Validierung dieser Aussage.

## Journal: echte Timeouts und zu strenge No-Match-Klassifikation

51 Fenster wurden versucht:

-46 Fenster: rc1,0 stdout-Bytes,0 stderr-Bytes, kein Timeout und keine Treffer.
-2 Fenster: rc0, jeweils ein bereinigter Treffer ausschließlich für Suchbegriff8081.
  Zeitfenster2026-04-05 bis04-12 und2026-09-20 bis09-27. Keine Nachrichteninhalte gesichert;
  ein Teilstring-Treffer8081 allein belegt keinen Bot-Verbindungsaufbau.
-3 Fenster: tatsächlicher Timeout nach15 Sekunden, Prozess-Rückgabecode-15,
  keine Ausgabebytes. Fenster2026-03-15 bis03-22,2026-04-12 bis04-19 und2026-05-10 bis05-17.
  Fehlerdateien enthalten monotone Start-/Endzeiten und Timeoutstatus. NAT wurde anschließend
  dennoch ausgeführt; vorherige Ergebnisse blieben erhalten.

Installiert: systemd255 (255.4-1ubuntu8.11). Der systemd-v255-Quellcode sieht bei --grep
und null Treffern bewusst einen Nichtnull-Rückgabecode vor (run(), n_shown==0):
https://github.com/systemd/systemd/blob/v255/src/journal/journalctl.c#L2412-L2417

Eine zusätzliche, ausschließlich lesende Abfrage unter UID1001 mit garantiert
unpassendem Suchmuster in einem festen Ein-Sekunden-Fenster reproduzierte rc1 bei
0 stdout-/stderr-Bytes in0,03548982 monotonen Sekunden. Sie erzeugte keine Journaleinträge.
Nachweis: `journal-no-match-semantics.json` im getrennten Validierungsverzeichnis.

Die46 identischen leeren Fenster entsprechen diesem erwarteten No-Match-Verhalten;
v2 hat sie durch seine allgemeine Nichtnull-Prüfung zu streng als Abschnittsfehler
klassifiziert. Die ursprünglichen ERROR-Artefakte bleiben unverändert. Diese semantische
Einordnung erfolgt ausschließlich in der Auswertung, nicht durch Änderung des Sammlers
oder nachträgliche Manipulation des Manifests. Selbst bei passender No-Match-Klassifikation
bleibt der Lauf wegen der drei echten Timeouts **INCOMPLETE**.

Vor einer künftigen Sammleränderung wäre eine journalctl-spezifische No-Match-Behandlung
mit strikten Bedingungen und Regressionstests nötig; andere Nichtnull-Codes oder stderr,
Parserfehler und Timeouts dürfen nicht pauschal als Erfolg gelten. Hier kein Codepatch
und keine weitere sudo-Ausführung.

## Bedeutung für den ersten Fehllauf

Die drei Timeouts sind ein konkreter Nachweis für diesen v2-Lauf. Sie beweisen nicht die
fehlende Exception des ersten Sammlers. Dessen Ursache bleibt ungeklärt, Journal-Timeout
weiterhin Hypothese. V1, seine Prüfsumme, fe2a806 und der alte Launcher sind unverändert.

## Entscheidung und unveränderter Zustand

Die Privilegiensicht klärt den aktuellen DNAT-Pfad, aber nicht den ursprünglichen Zweck
von Spicymilas zusätzlichem Anschluss. Die früher dokumentierte n8n-Mitgliedschaft,
nicht vollständig geklärte Workflow-/Remote-Historie und drei fehlende Journalfenster
verhindern einen belastbaren Entfernungsnachweis. Keine Transaktion für Recreate oder
Entfernung wird aktiviert. Bekannter Docker-Status unhealthy bleibt bestehen.

Frischer Vergleich nach dem Lauf: Produktionscontainer-IDs, Images, Config, HostConfig,
Mounts, Startzeiten, Restartzähler und beide Bot-Endpoints unverändert.
Compose-SHA256 weiterhin04c65475baa7a55067366b78295c8fa663df7996beca04980e191dded7dc3da0.
Alle42 Hardening-Dateien bytegleich. Detached Checkout sauber und unverändert bei
7c634d3b82572e8459d51c69f04dce82c624d766. Sammler v1 undv2 bytegleich mit ihren Pins.
Keine produktive Konfigurationsänderung, kein PR, kein Merge.
