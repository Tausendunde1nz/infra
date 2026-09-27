# Inventur v2: ausgewerteter Teilnachweis, keine Aktivierung

Nachweisverzeichnis:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/privilege-v2-20260927T113052Z-ba348f45`.
Alle 15 Ergebnisdateien stimmen mit den SHA-256-Werten im Manifest überein.
Version2.0.0, Quellcommit d233497d8c60bec768b2da348fd39ad899c2e5d3,
collection_finished=true. INCOMPLETE/review_required bleibt unverändert.
Keine neuen privilegierten Aufrufe bei dieser Auswertung.

## Bestätigte Ergebnisse

visudo: rc0, keine stderr-Daten, kein Timeout/Überlauf. Effektive sudo-Abfrage:
rc0, keine stderr-Daten. Include-Graph: /etc/sudoers bindet /etc/sudoers.d ein;
sechs Dateien insgesamt, keine weitere Include-Kette im erfassten Graphen.
Die fünf bereits bekannten chatops-Grants sind erneut bestätigt.
Neun weitere Definitionen konnten anhand ihrer exakten gespeicherten Zeilen-
Hashes mit Standarddefinitionen abgeglichen werden, ohne geschützte Inhalte
erneut lesen zu müssen: Defaults env_reset, mail_badpass, use_pty, secure_path;
root ALL=(ALL:ALL) ALL; %admin ALL=(ALL) ALL; %sudo ALL=(ALL:ALL) ALL;
@includedir /etc/sudoers.d; root ALL=(ALL) NOPASSWD:ALL in 90-cloud-init-users.
Kein Rückschluss allein anhand einer Ähnlichkeit oder des Dateinamens.
trendwatch-restart bleibt semantisch ungeklärt und wird nicht verändert.

Die geschützte PackageKit-Datei
/var/lib/polkit-1/localauthority/10-vendor.d/org.freedesktop.packagekit.pkla
ist zusätzlich vorhanden, Hash
`a6c05206be58929a74868d98361db8ce2d72fd9ce23e30fab50581636c0f7563`.
Sie gehört zum Paket packagekit. Ihre effektive Wirkung, Inhalt und die Frage,
ob ein Kompatibilitätsbackend sie auswertet, sind aus dem lexikalischen Datensatz
nicht bewiesen. Insbesondere ist eine neue JS-Sperre allein noch kein geprüfter
vollständiger Ersatz. Der Sammler hat unbekannte Regeln zu stark reduziert, um
diese semantische Lücke allein aus seinem Ergebnis zu schließen.

## Sitzungsabfrage: Fehler und unprivilegierte Ergänzung

loginctl show-session akzeptierte die verwendete kommagetrennte Property-Liste
nicht wie systemctl: rc0, aber leere Ausgabe. Das ist kein positiver Test.
Unprivilegiert mit jeweils separatem -p Id, -p User, -p Active, -p Remote,
-p State, -p Type, -p Class, -p Leader, -p Service wiederholt.
Die noch vorhandenen Sitzungen341783,335868,5705 hatten User1001, Remote=yes,
Active=yes; die letzten beiden waren closing. Keine lokale Sitzung simuliert.
Diese Beobachtung beweist nicht die zukünftige Autorisierung einer lokalen
Recovery-Sitzung. Historischer v2-Bericht und v2-Sammler bleiben unverändert.

## Dienst- und Aufruferbefund

Aus Requires/Before/After ergibt sich für die vier Dienste die Startabhängigkeit
S7 -> S8-Landing -> S8-Telegram -> S10-WMS (WMS benötigt zusätzlich S7 direkt).
Das ist ein Ordnungsnachweis, KEIN unterbrechungsfreier Neustartnachweis.
Stoppen eines erforderlichen Diensts kann abhängige Dienste beeinflussen;
S9-/S10-Health- und Nurture-Units liegen zusätzlich im Graphen. Drain, Timer,
In-flight-Aufträge und Wiederanlauf müssen vor Aktivierung bewertet werden.
Keine Dienste beendet oder neu gestartet, kein neuer Bot-/Webhook-Request.

Aufrufersuche:215 Einträge, davon25 Trefferdatensätze und190 Fehlerdatensätze.
187 OSError beinhalten verweigerte Symlink-Folgen; drei ValueError betreffen
übergroße historische Snapshot-Archive. Die Symlinkverweigerung bleibt erhalten,
ist aber keine vollständige Inventur der dahinterliegenden Unit-Ziele.
Golden-, Upload-Log-Leser und Trim-Skript sind erneut referenziert.
Keine Behauptung, alle legitimen alten Aufrufer seien entfallen.
Die Docs-Engine und aktive Golden-Fassung sind root-eigen; die beiden Docs-
Shellwrapper gehören dagegen chatops. Ihre effektive Ausführung als chatops ist
vom Eigentum zu unterscheiden. Frühere pauschale Formulierungen „root-eigene
Docs-Wrapper“ sind dadurch präzisiert, historische Dokumente nicht umgeschrieben.

## Konkreter Offline-Fortschritt

scripts/tu1nz_privilege_sudo_candidate.py ist eine reine Byte-Transformation
OHNE Datei-I/O oder Betriebssystemadapter. Sie bindet die drei betroffenen
Quelldateien an die tatsächlichen Inventur-Hashes, entfernt exakt einmal die
tee-/Golden-Zeilen und plant nur die zwei exklusiven Drop-in-Dateien zur Entfernung.
Andere Bytes, Regeln und Kommentare werden nicht verändert. Drift, zusätzliche
Pfade, fehlende/doppelte oder veränderte Grants führen zum Abbruch.
Sechs neue Tests bestanden; zusammen43 gezielte Tests grün.
Die Transformation wurde NICHT auf vollständigen produktiven sudoers-Bytes
und NICHT mit einem daraus erzeugten Gesamtvisudo-Kandidaten getestet, weil
v2 diese Rohbytes absichtlich nicht gespeichert hat. Kein Installationsnachweis.

## Verbleibendes Gate

Eine ausführbare Gesamttransaktion bleibt gesperrt: PKLA/Polkit-Semantik,
trendwatch-Regel, Unit-Symlinkziele, Socketabhängigkeiten, Drain/Wiederanlauf und
vollständiger Dateisystem-/Dienstrollback fehlen. Erst eine gezielte geschützte
semantische Nachprüfung kann die nicht gespeicherten Inhalte klären. Der
Zustandsmodelltest ersetzt das nicht. Keine Installation, Gruppenänderung,
Dienständerung oder neue sudoers-/Polkit-Regel. Kein PR.
Nach diesem Dokumentationscommit verhindert die Commitbindung des v2-Launchers
eine versehentliche Wiederholung; kein Launcher wird umgeschrieben oder gestartet.
