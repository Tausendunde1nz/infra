# Abschluss: Untersuchung und Schutz, keine Healthcheck-Aktivierung

## Verbindliche Betriebsentscheidung

Spicymilas zusätzlicher Endpoint in tausendunde1nz_net bleibt unverändert erhalten.
Sein historischer oder seltener Zweck ist nicht abschließend geklärt. Der aktuell
veröffentlichte Pfad8090 →172.21.0.2:8080 benötigt diesen Endpoint nicht.
Mommyramona verwendet tausendunde1nz_net nachweislich als Default-Route und DNAT-Ziel
8081 →172.25.0.2:8080. Die gemeinsam genutzte Netzwerkstruktur wird nicht geändert.

Der interne Spicymila-Healthcheck bleibt vorerst auf dem bekannten falschen Port8090.
Docker meldet deshalb unhealthy; Anwendung auf8080, Proxy-Endpunkte und Monitoring
funktionieren laut den gesicherten Prüfungen. In diesem Abschlusslauf wurden keine
neuen Bot-, Webhook- oder externen Testrequests ausgelöst. Der Healthstatus ist hier
kein Anlass für eine automatische Neuerstellung.

**Keine automatische Neuerstellung**, solange die zusätzliche Netzwerkverbindung nicht
verlustfrei modelliert oder durch eine vollständig getestete Transaktion abgesichert ist.
Der reine Netzwerk-Guard prüft die Übereinstimmung deklarierter und tatsächlicher
Netzwerknamen. Ein positives Ergebnis ist notwendig, aber nicht hinreichend für die
Erhaltung von Aliasen, IPAM, Routing und sämtlichen Endpoint-Einstellungen.
Der Guard ist eine reine Bibliotheksfunktion; keine neue Live-Automatisierung wird installiert.

## Bewusst begrenzter PR

Der finale Diff enthält ausschließlich Untersuchungs-/Recovery-Dokumentation, den reinen
Netzwerk-Guard, den lesenden Sammler2.1 und zugehörige Tests/CI-Anbindung. Der Compose-Patch
8090 →8080 und der gesamte ausführbare Apply-/Rollback-/Recreate-Transaktionscode werden
nicht integriert. Private Sicherungen und rohe Inspect-/Journal-/Umgebungsdaten bleiben
außerhalb Git. Auch der erste Sammler ist nicht Teil des finalen aktuellen Baums;
seine bytegleiche historische Fassung bleibt über Commitfe2a806 verfügbar.

Historische Fehlversuchs-, Recovery- und Vorbereitungsdokumente sind unverändert erhalten.
Ihre damaligen Befehls-/Dateiverweise dokumentieren die Vergangenheit und sind ausdrücklich
**keine aktuellen Aktivierungsanweisungen**. Der alte private Launcher bleibt unverändert
und wegen seiner Pins ungültig. Kein sudo-Lauf und keine Live-Aktivierung in diesem Auftrag.

## Sammler2.1

Die Datei behält ihren etablierten Namen tu1nz_spicymila_dependency_readonly_v2.py;
VERSION ist2.1.0. Nur das Ergebnis eines Aufrufs von /usr/bin/journalctl mit --grep darf
NO_MATCH werden, wenn gleichzeitig rc1, timeout=false, stdout_bytes=0, stderr_bytes=0,
keine Datensätze und ausschließlich der vom generischen Runner erzeugte Rückgabecodefehler
vorliegen. Der originale Rückgabecode1 bleibt als Beobachtung erhalten. Jede weitere
Fehlerart, Parserabweichung, Ausgabe, fehlendes Feld, anderer Nichtnull-Code oder ein
Timeout bleibt ein Fehler. Die Klassifikation erzeugt ein neues Resultatobjekt.

Die NO_MATCH-Korrektur wirkt nur auf zukünftige Läufe. Das ursprüngliche v2-Manifest
und sämtliche104 referenzierten Ergebnisdateien bleiben bytegleich und INCOMPLETE.
Die drei nachgewiesenen Timeouts sind unverändert; der erste Fehllauf bleibt ungeklärt.

## Validierung und Integrationsbasis

Aktueller control-main56a642a9df715b8d4a50b38bb7d401a1066ca9b9 wurde konfliktfrei per Merge
in den separaten Arbeitsbranch übernommen. Kein Rebase oder Force-Push, detached
Produktionscheckout unverändert.40 gezielte Offline-Tests bestanden, einschließlich
aller NO_MATCH-Grenzfälle, Prozessgruppenbeendigung, Signale, atomarer Teilergebnisse
und Netzwerk-Guard. Vollständiger108-Schritte-Lauf: alle108 Schritte im isolierten Checkout bestanden.
CI und vollständiger PR-Diff müssen vor dem Merge grün bzw. erwartungsgemäß sein.

## Getrennter offener technischer Punkt: eigentlicher Healthcheck-Fix

Status: OFFEN / nicht aktiviert. Ein eigener zukünftiger Change darf8090 →8080 intern
korrigieren, sobald alle Voraussetzungen erfüllt sind:

1. Zweck oder Entbehrlichkeit des zusätzlichen Spicymila-Endpoints geklärt.
2. Verlustfreies Netzwerkmodell oder vollständig getestete Transaktion einschließlich
   Teilzuständen, Fehler-Injektion und exakter Wiederherstellung beider Endpoints.
3. Geplantes Wartungsfenster mit automatischem Rollback und unabhängiger Recovery-Möglichkeit.

Dieser Punkt ist kein Aktivierungsauftrag. Keine Änderung an Portfreigaben, Anwendung,
Image, Ressourcen, anderen Containern, Firewall oder Tailnet ist darin enthalten.

Nachweisverzeichnis: `/opt/tu1nz_repos/network-hardening-private-2026-09-22/bot-closeout-20260927T102406Z/`.
Historisches v2-Manifest und104 Ergebnisdateien erneut hashgeprüft und unverändert.
Vollständiger aktueller Branch-Diff geprüft: keine privaten Rohdaten, erkannten Secrets,
Compose-Dateien, ausführbaren Aktivierungslauncher oder Produktions-/Deploymentänderungen.
