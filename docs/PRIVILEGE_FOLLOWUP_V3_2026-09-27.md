# Geschützter Nachsammler v3 und praktische Offline-Wiederherstellung

Fortsetzung ab d67c8e4028ae837a830423d9f5ef3544845083d3 auf
security/codex-privileged-ops-2026-09-27. Kein PR, keine Live-Migration.
Alte Sammler und Berichte werden nicht korrigiert oder überschrieben.

## Neue Erfassungsgrenze

Der neue Auftrag erlaubt ausdrücklich bytegenaue private Rohdaten. V3 speichert
sudoers-Dateien, Includes, Polkit-Dateien, relevante Units/Skripte und geschützte
Konfigurationen unverändert als nummerierte raw-*.bin. Diese Dateien können
Geheimnisse enthalten und dürfen niemals ungeprüft im Chat oder Git erscheinen.
Metadaten und Befehlsausgaben bleiben ebenfalls ausschließlich im privaten
Ergebnisverzeichnis. Im Repository stehen nur Code, Tests und diese Beschreibung.

Ergebnisverzeichnis wird neu/exklusiv unter
/opt/tu1nz_repos/network-hardening-private-2026-09-22/
als privilege-v3-<UTC>-<Zufall> angelegt. Verzeichnis0700, alle Dateien0600.
Dirfd-gebundenes Schreiben, keine Symlinks im Ausgabe-Ancestry; atomare temporäre
Datei, fsync, rename, Verzeichnis-fsync. Dateitypen/Modi und alle abschließenden
SHA-256 prüft der separate unprivilegierte Validator. Der Nachsammler schreibt
keine Live-Dateien und startet keinen Watchdog. Standardmäßige sudo-/OS-Audit-
Protokollierung ist nicht mit einer Konfigurationsänderung gleichzusetzen.

## Inhalt

- Vollständige sudoers-Bytes mit rekursivem Include-/Includedir-Graph, relativen
  und quotierten Pfaden und %h-Expansion. Andere unbekannte Syntax: Fehler,
  keine stillschweigende Interpretation. Symlinkketten mit kanonischen Zielen,
  Elternmetadaten und ACLs. visudo -c sowie sudo -n -ll -U chatops als Rohbelege.
- Alle zugänglichen systemweiten/lokalen .rules/.pkla-Dateien, PackageKit-Action-
  Metadaten, dpkg-Installationsstatus/Versionen/Dateilisten und Polkit-Unit.
  Vorab lesend festgestellt: packagekit1.2.8-2ubuntu1.2,
  polkitd124-2ubuntu1.24.04.2. Leere Versionsauskunft zu polkitd-pkla ist allein
  kein endgültiger Backend-Nachweis; genauer Status und Dateilisten folgen.
- Reale logind-Sitzungsmerkmale mit einzelnen -p-Argumenten. Kein Nachbau einer
  lokalen Sitzung. pkcheck für sämtliche PackageKit-Action-IDs ausschließlich
  gegen die echte, noch lebende SSH-Wrapper-PID, deren Startticks und UID1001.
  Kein --allow-user-interaction, kein interner Agent, kein PackageKit-Aufruf,
  kein Widerruf temporärer Autorisierungen. rc0/rc1 sind zu bewertende Antworten,
  andere Codes Prüfprobleme. Eine entfernte Sitzung beweist keinen lokalen Fall.
- trendwatch-restart vollständig privat; absolute Referenzen, genannte Units und
  konkrete systemctl-Ziele werden zusätzlich gelesen, niemals ausgeführt.
- Vier öffentliche Dienste plus Golden/Docs/Trendwatch und TU1NZ-Abhängigkeiten:
  Fragment/Source/Drop-ins, ExecStart/Pre/Post/Stop/Reload, EnvironmentFiles,
  Arbeits-/Runtime-/State-/Logverzeichnisse, UID/GID/PID, Abhängigkeiten und
  Restart-/Stopvorgaben. Interpreter aus Shebangs und laufenden Exe-Links.
  Unaufgelöste Variablen/Escapes bleiben Fehler mit Rohbeleg, keine Vermutung.
- Unix-Sockets und TCP/UDP-Listener rein lesend über ss; Socket-Inodes der
  relevanten Prozesse und deren tatsächliche Gruppen. Aufruferreferenzen in
  festen Skript-/Unit-/Cron-/Infra-Pfaden. Keine Payloads und keine Bot-Anfragen.

Dateien werden stabil und begrenzt gelesen; Drift und unlesbare/überlange Inputs
bleiben offene Befunde. Pro Kommando feste Umgebung, eigene Prozessgruppe,
20-Sekunden-Limit und8MiB je Stream. stdout/stderr/rc/Timeout werden getrennt
privat abgelegt. Ein Fehler löscht keine früheren Daten. Manifest bleibt
INCOMPLETE, bis ein Mensch/Agent den gesamten Befund semantisch ausgewertet hat;
collection_finished ist davon getrennt. Exit2 mit verwertbarem Teilbefund,
Exit3 bei Fehler vor sicherer Ergebniserstellung. SIGINT/SIGTERM erhalten das
Teilmanifest. Dateien/Manifeste werden nicht als vollständige Regelanalyse ausgegeben.

## Bindung und Ausführung

Nach Commit erzeugt scripts/tu1nz_privilege_followup_launcher.py einen neuen
Launcher aus genau Commit und finaler Sammler-SHA. Er prüft Remote-Worktree-HEAD,
eingelesene Skriptbytes und Git-Blob bytegenau VOR sudo. Genau diese Bytes werden
in-memory an /usr/bin/python3 -I -B übergeben und erneut gehasht. Der Sammler
importiert keinen benutzerveränderbaren Repository-Code. Manifest enthält
Commit, Version und SHA. Alte Launcher bleiben unangetastet/ungültig.
Das Generatorprogramm führt selbst nichts aus. Genau eine persönliche sudo-
Eingabe ist vorgesehen, erst nach neuer expliziter Bereitschaft des Benutzers.
Die Live-Migration braucht weiterhin eine separate Aktivierungsfreigabe.

## Dienstplan, bis zur Inventurauswertung gesperrt

Belegte Startordnung: S7 -> S8-Landing -> S8-Telegram -> S10-WMS; Stoppen nur
nach Drain in umgekehrter Ordnung. S9-/S10-Health/Nurture und Timerabhängigkeiten
müssen vorher mitbetrachtet werden. Noch keine maximale sichere Unterbrechung
behaupten: TimeoutStopSec allein ist kein Verfügbarkeitsbudget. Healthchecks,
Ports, Socketbedarf und erlaubtes Wartungsfenster aus echten Konfigurationen
ableiten. Keine Nachrichten/Webhooks als künstliche Funktionsprobe.
Neue SSH-Sitzung nach Gruppenänderung, alle alten Docker-GIDs erfassen; kein
killall für UID1001. Jellyfin ohne Docker-GID bleibt unverändert.

## Praktische Offline-Transaktionssimulation

scripts/tu1nz_privilege_fs_simulation.py akzeptiert nur ein neues, leeres,
benutzereigenes0700-Verzeichnis mit festem Fixture-Präfix. KEIN Live-Adapter.
Es erzeugt sudoers-, Polkit-, group/gshadow-, Unit-/Symlink-, Zustands- und
Broker-Fixtures. Vorher-JSON plus SHA, Inhalt, UID/GID, Modi, mtime, Symlinkziele
und tatsächliche Linux-xattrs einschließlich Access-/Default-ACLs werden erfasst.
Die Wiederherstellung betrifft ausschließlich den Fixture-Baum. Jeder Pfad muss
relativ sein, kein .. und keine Symlink-Ancestry. Keine fremden Dateien.

Tests: Erfolg und manueller Restore; Fehler vor/nach jeder der acht Phasen;
Watchdog-Auslösung in jeder Phase; vier fehlschlagende Dienststarts; SSH-Abbruch;
fehlende Datei, unbekannte Ausgangsregel und korrupte Sicherung. Die Dateien,
Symlinkziele, Modi, UID/GID, mtime und ACL-xattrs stimmen nach Restore exakt.
Dienstzustände und Reihenfolge sind reproduzierbare Fixtures, KEINE echten Units.
Getestet wird mit dem unprivilegierten Dienstkonto in isolierten Linux-Dateien.
Root-Eigentumswechsel, echte Dienste, Root-Timer, PAM/SSH-Gruppenerneuerung und
öffentliche Verfügbarkeit können erst in der später überwachten Transaktion
bewiesen werden. Inodes/ctime und beendete Prozessspeicher sind nicht reversibel;
atime wird nicht als stabiler Prüfwert benutzt. Kein falscher Live-Rollbacknachweis.

Die macOS-System-Pythonumgebung besitzt keine Linux-ACL-xattr-API. Die vollständige
Dateisystemsimulation wird daher auf dem Linux-Server ohne sudo ausgeführt; ihre
ACL-Anforderungen werden nicht abgeschwächt. Der Launcher bleibt Python3.9-
kompatibel, während der Sammler für den vorhandenen Server-Python getestet wird.

## Noch fehlend

Der privilegierte v3-Lauf selbst: exakte trendwatch-Regel/Ausführungskette,
PKLA-Backend/Priorität und aktuelle nicht-interaktive Autorisierung, vollständige
relevante Unit-/Environment-/Pfadbelege. Erst danach finale Broker-/Ersatzdateien,
exakter Polkit-Diff, Dienst-Drain und ausführbarer Root-Transaktionsadapter.
Ungeklärte Rechte dürfen nicht durch eine heuristische Ersatzregel kaschiert werden.

## Abschließende Offline-Validierung

65 Tests bestanden auf Linux-Python ohne sudo, einschließlich aller bisherigen
43 Tests und22 neuer Tests. Nachweis:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/followup-v3-finaltest-72nejihz/tests.txt.
Keine PKCheck-Autorisierungsprüfung wurde im Vorbereitungslauf ausgeführt; nur
die vorhandene --help-Ausgabe wurde gelesen. Kein alter Launcher gestartet.
