# Privilegienmigration: Sammler v2 und gesperrter Transaktionsentwurf

Basis cbcb9b4eeac2c7287d47c6262626c369cf73ff37, Branch
security/codex-privileged-ops-2026-09-27. Kein PR, keine Live-Aktivierung.
Remote control-main wurde lesend mit e266830433e139b3e4c8f7ed7c3fe88fd392bba4
festgestellt. Keine ungeprüfte Integration dieser zwischenzeitlichen Änderungen.

## Neuer Sammler

scripts/tu1nz_privilege_inventory_v2.py ist vollständig getrennt von v1/v1.0.1.
Version 2.0.0. Der nach Commit erstellte private Launcher bindet erwarteten Commit
und finale Skriptbytes per SHA-256; derselbe Commit und Hash werden ins Manifest
übernommen. Der alte Launcher bleibt unverändert und wegen alter Hashbindung gesperrt.
Keine sudoers-Freigabe für den Sammler; genau ein persönlich authentifizierter
sudo-Aufruf von Python -I -B mit bereits eingelesenen, geprüften Skriptbytes.
Keine userseitigen Pfade/Argumente im Sammler, feste Umgebung, keine Shell.

Der Sammler liest sudoers mit rekursiven @include/#include und includedir-Ketten,
relativen und quotierten Pfaden sowie Fortsetzungszeilen. Include-Verzeichnisse
überspringen Namen mit Punkt oder abschließendem ~. Zyklen, %h/andere Prozent-
Expansionen, Symlinks und nicht verstandene Syntax sind offene Fehler, keine
stillschweigende Freigabe. Höchstens 256 Include-Dateien. Es ist absichtlich kein
Ersatz für den sudo-Parser: visudo -c -f /etc/sudoers und sudo -n -l -U chatops
werden zusätzlich ausschließlich lesend ausgeführt. Keine Authentifizierung
von Unterkommandos, keine Sicherheitslücke zur Privilegienbeschaffung.

Numerische ACLs mit getfacl -p, Eigentümer, Modi, Inodes, Hashes und Elternpfade;
Polkit-System-/Lokalregeln und PackageKit-XML-Defaults; reale logind-Sitzungen;
PID/Startticks/GIDs/cgroups/Socket-Inodes; sieben fest benannte Units mit
Abhängigkeiten und Startweg-Hash; feste Aufrufersuchen in Units, Skripten,
Crontabs und Infra-Repository. Prozessargumente und Umgebungswerte werden nicht
veröffentlicht. Unbekannte Policy-Literale werden gehasht statt ungefiltert
protokolliert. Eine unbekannte Regel bleibt semantisch ungeklärt, auch wenn ihre
Quelldatei vollständig gelesen wurde. Symlinkpfade und übergroße Dateien werden
nicht blind verfolgt. Fehlende Abdeckung bleibt ein Blocker.

Jede Kommandoprüfung erfasst stdout/stderr separat als Länge und SHA-256,
Returncode, Timeout, Überlauf und monotone Zeiten. stdout wird nur über den
jeweiligen Feldfilter ausgegeben; stderr niemals als Rohtext. Je Stream 1 MiB,
20 Sekunden; Prozessgruppe wird auch bei überlebenden Kindprozessen beendet.
Es werden nur Kindprozesse des Sammlers beendet, keine bestehenden Dienste.
Abschnittsergebnisse werden 0600 per exklusiver temporärer Datei, fsync und
rename publiziert. Ergebnisverzeichnis 0700, dirfd-gebunden, keine Symlink-
Ancestry. Nach jedem Abschnitt ein neues atomisches Manifest; SIGINT/SIGTERM
beenden den Lauf mit Teilmanifest. Erfolgreiche Abschnitte bleiben erhalten.

Der Sammler hat zwei getrennte Aussagen: collection_finished zeigt das Erreichen
des Endes; Status INCOMPLETE und Exit2 bleiben bis zur fachlichen Auswertung
bestehen. Fehler vor sicherer Ergebniserstellung: Exit3. Ein vollständiger
privilegierter Sicherheitsnachweis wird nicht automatisch aus Exit0 abgeleitet.
Nur neue Nachweise unter /opt/tu1nz_repos/network-hardening-private-2026-09-22
werden geschrieben. Normale sudo-/Betriebssystem-Auditmeldungen sind unvermeidbare
Systemprotokollierung, keine durch den Sammler aktivierten Konfigurationsänderungen.

## PackageKit: belegte Bedingungen und Grenzen

Die ausgelieferte Regel gibt upgrade-system und trigger-offline-update für
subject.active && subject.local && sudo-Mitglied frei. Für andere Kombinationen
liefert diese Regel kein YES; daraus folgt NICHT automatisch die effektive
Ablehnung, weil weitere Regeln und Action-Defaults greifen können.

| Aktion | allow_any | allow_inactive | allow_active |
|---|---|---|---|
| system-sources-refresh | auth_admin | yes | yes |
| system-network-proxy-configure | auth_admin | auth_admin | yes |
| upgrade-system | no | no | auth_admin |
| trigger-offline-update | auth_admin | auth_admin | yes |
| clear-offline-update | auth_admin | auth_admin | yes |

Weitere Installations-, Reparatur-, Downgrade- und Updateaktionen besitzen
überwiegend auth_admin/auth_admin_keep; die vollständige XML-Liste wird gesammelt.
Admin-Authentifizierung und gecachte Autorisierung sind nicht gleichbedeutend
mit einer permanenten NOPASSWD-Regel. Reale logind-Merkmale sind für lokale,
entfernte, aktive/inaktive Zustände zu prüfen. Keine Sitzung wird simuliert.
Keine PackageKit-Aktion oder interaktive Polkit-Prüfung wurde ausgeführt.

Spätere sichere Negativprüfung: pkcheck für eine echte, frisch bestätigte
chatops-PID samt Startzeit und UID sowie eine feste PackageKit-Action-ID, OHNE
--allow-user-interaction. Es wird nur Autorisierung angefragt, nicht die Aktion
aufgerufen. rc1 ist Ablehnung; rc0 unerwartete Autorisierung; andere Codes sind
Prüffehler. Keine erfundene lokale/aktive Identität und keine Schlussfolgerung
über nicht vorhandene Sitzungstypen. Vollständige Semantik unbekannter JS-Regeln
ist durch die lexikalische Inventur nicht bewiesen.

Zielvorschlag: frühe root-eigene Polkit-Regel, die für chatops ausschließlich
org.freedesktop.packagekit.* mit NO beantwortet, andere Nutzer unangetastet.
Dateiname/Reihenfolge erst nach vollständiger Regelinventur; keine bestehende
frühere Regel darf die Sperre übergehen. Abhängigkeiten der legitimen Programme
prüfen. Allgemeines passwortpflichtiges sudo bleibt für Notfälle erhalten.
Andere Polkit-Aktionen und gecachte Berechtigungen müssen separat bewertet
werden; die PackageKit-Sperre beweist nicht allein eine vollständige Rootgrenze.

## Konkrete Migrationsreihenfolge (noch nicht ausführbar)

1. Neue Inventur gegen Hashes, Include-Graph und erwartete Dateien abgleichen.
   Alle unbekannten Regeln/Prozesse und alle Abhängigkeiten klären. Keine Mutation
   bei Drift, ungeklärter Semantik oder fehlendem Diensttest.
2. Root-geschützte Vorher-Sicherung: gesamte tatsächlich einbezogene sudoers-
   Konfiguration, konkrete Polkit-Dateien, Broker-/Ersatzdateien oder Abwesenheit,
   /etc/group und /etc/gshadow mit Besitzer/Modi/ACLs, relevante Unit-/Drop-in-
   Dateien, aktuelle Dienstzustände und Gruppenmitgliedschaften. Rohbackups
   ausschließlich root-lesbar, nie Git. Frische Zeitstempel und Hashmanifest.
3. Unabhängiger root-eigener systemd-Watchdog mit großzügiger Frist vor jeder
   Mutation. Kein Cron, keine Abhängigkeit von chatops oder der SSH-Sitzung.
   Getesteter Notzugang und Rollbackmodul sind harte Aktivierungsvoraussetzungen.
4. Root-eigenen Broker plus benötigte Ersatzdateien atomar aus geprüftem Staging
   installieren. Feste Operationskennungen, feste Container-/Unit-/Pfadlisten;
   keine freie CLI, kein Docker-Socket an chatops, keine schreibenden Operationen.
   Interpreter/Imports und sämtliche Eltern müssen gegen chatops geschützt sein.
5. Sudo-Kandidaten isoliert UND im vollständigen Include-Kontext mit visudo prüfen.
   Nur belegte Grants entfernen: tee und altes Golden aus /etc/sudoers;
   99-dokuagent-pandoc und chatops-nopass nur entfernen, wenn tatsächlich exklusiv
   diese Grants enthalten. Sonstige Regeln erst nach semantischer Prüfung.
   Exakte Brokerbefehle NOSETENV/NOPASSWD, kein Wildcard und kein ALL.
6. Geprüfte PackageKit-Sperre aktivieren; vollständige sudoers-Prüfung wiederholen.
7. chatops aus docker entfernen. Neue unabhängige SSH-Verbindung herstellen;
   Gruppenstand und nicht schreibbaren Socket nachweisen, sudo -k ausführen.
8. Vier Dienste separat anhand Dependency-Graph, Socketbedarf, Inflight-Arbeit
   und Health-Gates erneuern. Noch KEINE Reihenfolge behaupten: deren sichere
   Topologie ist Ergebnis der ausstehenden Inventur. Nicht alle chatops-Prozesse
   pauschal beenden. Jellyfin ohne Docker-GID bleibt unangetastet. Benutzer-manager,
   tmux, ssh-agent und alte Sitzungen gesondert kontrolliert ersetzen/beenden.
   Watchdog und neue SSH-Sitzung müssen unabhängig weiterlaufen.
9. Positivtests sämtlicher Brokeroperationen, echte PDF-Erzeugung ohne Push,
   Golden-/Loggingersatz, vier Dienste, Monitoring und SSH. Negativtests nach
   sudo -k: direkte alte Kommandos, Interpreter, Docker CLI/Socket, generische
   Dienst-/Firewall-/Dateibefehle, Zusatzargumente, unbekannte Operationen,
   manipulierte Umgebung. Kein verbleibender Prozess mit Docker-GID.
10. Frische Root-Nachprüfung, stabile Beobachtung, nur bei vollem Erfolg
    finalize-install: eng begrenzter Abbruch ausschließlich des eigenen Watchdogs.

## Funktionsersatz und bisherige Offline-Nachweise

Docs: aktive root-eigene Python-Pipeline erzeugt PDF als chatops ohne Pandoc/sudo.
Frisch unter synthetischen Statusdaten eine echte PDF erzeugt, alle Nicht-PDF-
Kommandos während der Erzeugung blockiert. Zehn vorhandene Pipeline-Tests bestehen,
inklusive No-Git-Staging, Inhalt/Rendering, Fehlerfällen und Restore. Push-Tests
benutzen ausschließlich temporäre lokale Bare-Repositories, keinen externen Push.
Nachweise: privilege-v2-pdf-tests-ralbvbkh im bestehenden privaten Nachweisverzeichnis.
Golden: aktive root-eigene /usr/local/bin-Fassung läuft als chatops ohne sudo;
kein probeweiser Aufruf wegen Push-/Telegram-Nebenwirkungen. Alte Aufrufer bleiben
zu prüfen. Logging: unprivilegierter Ersatz bevorzugt; feste /tmp-Datei im
Trim-Skript und alle Aufrufer/Identitäten müssen vor Entfernung geklärt werden.
mkdir/chown: nur exakt bestätigte Zielverzeichnisse einmalig korrigieren, keine
pauschale Rekursion. Docker: v1-Broker nur Read-only-API mit fester Containerliste
und feldweiser Redigierung; keine Containerlogs ungefiltert und kein inspect Env.

## Rollback und Grenzen

Rollback läuft als unabhängiger Root-Prozess, auch nach Abbruch einer SSH-Sitzung.
Er stellt nur eigene, vom Vorher-/Kandidatenhash bestätigte Dateien, ACLs und
Gruppeninformationen wieder her. Unerwartete fremde Änderungen führen zu explizitem
Recovery-Alarm statt Überschreiben. Nur betroffene Dienste in ihrem alten Zustand
wiederherstellen/neu starten; neue SSH-Gruppenprüfung und Gesundheitstests.
Broker und neue Regeln bei ursprünglicher Abwesenheit entfernen. Bei Fehlern des
Rollback niemals Erfolg oder Finalisierung ausgeben; Watchdog/Recovery erhalten.
Gruppen-/Konfigurationsrollback bedeutet nicht Rekonstruktion beendeter Shell-
Speicherzustände oder Rücknahme externer Dienstnebenwirkungen. Deshalb ist ein
freigegebenes Wartungsfenster mit kontrolliertem Drain ein notwendiges Gate.

scripts/tu1nz_privilege_migration_model.py hat KEINEN OS-Adapter. Es testet nur
Gates und Zustandsübergänge: Fehler an allen elf Phasen, unbekannte Regeln,
fehlende Aktivierungsfreigabe und fehlgeschlagener Rollback. Kein Nachweis eines
realen Dateisystem-/Dienst-Rollbacks. Dieser muss erst nach der Inventur als
separat geprüfte Implementierung mit echten isolierten Fixtures entstehen.

25 neue Offline-Tests plus 12 bestehende Sammlertests bestehen auf dem Server;
zusätzlich zehn PDF-Pipeline-Tests. Enthalten: echte Kindprozess-/Enkelprozess-
Timeoutbereinigung, Umgebungsisolierung, Ausgabegrenzen, Parserfehler, Symlinks,
FIFO, Include-Zyklus, Hashdrift, atomare Teilmanifeste, Rename-Fehler und Signale.
Kein privilegierter v2-Lauf und keine Live-Migration in dieser Vorbereitung.
