# V3-Auswertung: Regeln geklärt, Live-Transaktion noch gesperrt

Privater Nachweis: privilege-v3-20260927T120945Z-9867d70d unter dem bestehenden
network-hardening-private-2026-09-22-Verzeichnis. Der erste Leseversuch traf den
noch laufenden Sammler vor Übergabe der Eigentümerschaft; PermissionError war
kein Datenverlust. Nach Ende:0700-Verzeichnis/0600-Dateien,1.125 Dateien korrekt
gegen file_hashes validiert, collection_finished=true, keine globale Exception.
Originalmanifest bleibt INCOMPLETE mit33 gemeldeten Befunden. Kein Original
wird nachträglich umklassifiziert. Alle Rohtexte bleiben privat, nicht Git.

## Autorisierung korrekt auswerten

17 PackageKit-Prüfungen gegen den echten SSH-Prozess UID1001:
16x Exit2 mit exakt gleichem60-Byte-Authentifizierungshinweis, einmal Exit1
(upgrade-system). Kein Exit0, kein Timeout und keine PackageKit-Aktion.
Die installierte pkcheck(1)-Dokumentation definiert Exit2 ausdrücklich als
nicht autorisiert wegen fehlendem Agenten oder fehlender Interaktionsfreigabe;
Exit126/127 wären Argument-/Prüffehler. Der v3-Sammler hat Exit2 zu streng als
Kommandofehler markiert. Neue Offline-Auswertung behandelt NUR den exakt
belegten Hinweis mit leerem stdout, passender SHA und ohne Timeout/Überlauf als
NOT_AUTHORIZED_AUTH_REQUIRED. Unbekannte stderr-Ausgaben bleiben Fehler.
69 gezielte Tests bestanden, darunter vier neue Klassifikationstests.
Kein privilegierter Wiederholungslauf erforderlich, keine gespeicherten Daten geändert.

Alle fünf im Sammler erfassten realen Sitzungen sind Remote=yes, Active=yes;
zwei befinden sich im Zustand closing. Keine lokale Sitzung erzeugt/simuliert.
Die negativen Resultate beweisen ausschließlich den geprüften entfernten Kontext.

## PackageKit-Backend und statische lokale Wirkung

packagekit installiert1.2.8-2ubuntu1.2; polkitd installiert124-2ubuntu1.24.04.2.
polkitd-pkla Status un, keine installierte Version/Dateiliste. Zusätzlich fehlen
/usr/sbin/pkla-check-authorization und die49-polkit-pkla-compat.rules.
Die vorhandene Vendor-PKLA enthält:
Identity=unix-group:sudo; Actions upgrade-system und trigger-offline-update;
ResultAny=no, ResultInactive=no, ResultActive=yes.
Das spricht für eine nicht ausgewertete historische PKLA-Datei im vorliegenden
Javascript-Backend. Kein beliebiges zukünftiges Backend wird dadurch ausgeschlossen.
Die vorhandene JS-Regel erlaubt dieselben beiden Aktionen bei active && local &&
sudo-Gruppe. Dazu kommen die separat erfassten PackageKit-Action-Defaults.
Eine spätere explizite chatops-Sperre muss diese gesamte Action-Familie und die
vollständige Regelreihenfolge berücksichtigen. Passwortpflichtiges allgemeines
sudo bleibt bestehen. Keine Polkit-Regel wurde geändert.

## trendwatch-restart ist kein chatops-Grant

Die exakte Regel lautet: daniel ALL=(root) NOPASSWD:
/usr/local/bin/trendwatch_restart.sh.
Sie gilt ausdrücklich für daniel, nicht chatops. Der Zielpfad existiert derzeit
nicht; /usr/local/bin ist nicht durch chatops direkt beschreibbar. Es gibt daher
keine vorhandene Skript-/Interpreter-Ausführungskette an diesem Regelziel.
trendwatch.service/timer haben keine FragmentPath und sind inaktiv; andere
Trendwatch-Units existieren separat. Eine gleiche Namenskomponente ist kein
Beleg, dass sie von dieser verwaisten Regel gestartet werden.
Die Regel wird in der chatops-Migration nicht eigenmächtig entfernt oder ersetzt.

## Exakter sudo-Kandidat erstmals mit Originalbytes geprüft

Privater Teststand:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/privilege-sudo-offline-120b8ird.
Die bereits versionierte Byte-Transformation akzeptiert die tatsächlichen drei
Originaldateien anhand ihrer gebundenen SHA-Werte. Zwei exakte tee-/Golden-Zeilen
werden aus /etc/sudoers entfernt, ausschließlich99-dokuagent-pandoc und
chatops-nopass zur Entfernung vorgesehen. Alle anderen Includedateien bleiben.
SHA des resultierenden produktiven sudoers-Kandidaten:
af65c80153ab7a5d25c6a58d4825455102c355bb53f09dbd668afc0928c3d9a4.
Für den Offline-Check wurde NUR die Includedir-Adresse auf den privaten kopierten
Baum umgebogen. visudo -c -f meldet rc0 und keine stderr-Daten.
Dies prüft den Entfernungskandidaten, noch NICHT eine vollständige neue
Broker-Sudoers-Konfiguration. Kein produktiver Pfad geändert.

## Dienstprüfung und verbleibende Abhängigkeiten

Die vier öffentlichen Dienste laufen als chatops aus adult-publishing-core.
Unit-Belege enthalten keine Docker-Socket-Referenz. Eine zusätzliche lesende
Suche im Anwendungs-src nach docker.sock, import/from docker und docker exec/
inspect fand keine Treffer. Das ist ein Indiz, kein dynamischer Funktionsbeweis.
Die bekannte Startordnung S7 -> Landing -> Telegram -> WMS und die umgekehrte
Stopordnung müssen In-flight-Arbeit und weitere Health/Nurture-Abhängigkeiten
berücksichtigen. Es wurde keine künstliche Nachricht oder Restartprobe ausgeführt.

Sechs fehlende /run/credentials-Pfade gehören zu S9-/S10-Hilfsunits. Runtime-
Credentials können bei inaktiven Units fehlen; ohne Abgleich mit ihrem aktuellen
Unit-Zustand darf weder Fehlerfreiheit noch Verlust behauptet werden.
Weitere elf Lücken sind fehlende/verwaiste Unit-Verweise, unter anderem alte
Trendwatch-Timer. Sie bleiben dokumentiert, ohne pauschale Reparatur.

## Keine unberechtigte Abschlussbehauptung

Regelauswertung und konkreter sudo-Entfernungskandidat sind wesentlich weiter.
Die gesamte ausführbare Broker-/Installations-/Watchdog-Transaktion ist weiterhin
NICHT vollständig implementiert oder als Live-Rollback bewiesen. Die bislang
erfolgreichen Dateisystem-/ACL-Restoretests betreffen isolierte Fixtures.
Vor Aktivierung bleiben insbesondere exakter Broker/Funktionsersatz, Root-
Transaktionsadapter, Credential-/Drain- und Wiederanlaufgates sowie unabhängige
SSH-/Gesundheitsabnahme notwendig. Keine erneute allgemeine Freigabe zum
Vorbereiten erforderlich; jede Live-Aktivierung bleibt separat gesperrt.
