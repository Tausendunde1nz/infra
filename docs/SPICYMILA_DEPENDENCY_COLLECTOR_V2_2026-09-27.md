# Privilegierter Abhängigkeitssammler v2 — reine Vorbereitung, 2026-09-27

Status: 25 Offline-Tests bestanden. Kein sudo-Lauf, keine Produktionsaktivierung,
kein PR und kein Merge. Neue Dateien ersetzen keine historischen Nachweise.

## Historischer Fehllauf und mögliche Entstehung von Exit1

Commit `fe2a806c787584ad6e5013fe4019c9191e647d33` bleibt unverändert im Verlauf.
Sammler v1 `scripts/tu1nz_spicymila_dependency_readonly.py` ist bytegleich mit diesem Commit;
SHA256 `29ff4d5261e4f8fa3bcf0ac82a8763b02490bbe19dca402815a19accb3b6fd75`.
Der alte Aktivierungslauncher bleibt unverändert und ungültig.

Der äußere Python-Aufruf öffnete die Ergebnisdatei, rief sudo/Python mit stdout auf dieser
Datei auf und schrieb danach den Rückgabecode1 samt SHA256 der leeren Datei. Die vorhandene
Statusdatei beweist, dass dieser äußere Pfad bis zur Statussicherung gelangte. Ein Fehler
beim vorherigen Öffnen der Datei hätte nicht diesen Status erzeugt. Die beobachtete
root-Python-/journalctl-Prozesskette belegt einen gestarteten privilegierten Sammler.

In v1 gibt es keine explizite erfolgreiche Teil-Ausgabe: `main()` baut alle Datei-Metadaten
im Speicher auf und wertet anschließend im Argument von print/json.dumps nacheinander
`journal_metadata()` und `nat_metadata()` aus. Erst danach würde stdout beschrieben.
Nicht abgefangene Exceptions in einer dieser Stufen führen typischerweise zu Python-Exit1:

- Journal: subprocess.TimeoutExpired beim120-Sekunden-Limit, OSError beim Prozessstart,
  Dekodierungs-/Speicherfehler beim vollständigen capture_output-Puffer.
- NAT: subprocess.TimeoutExpired beim15-Sekunden-Limit oder OSError beim Prozessstart.
- Weitere unerwartete Exceptions beim Aufbau/Serialisieren/Schreiben der Gesamtausgabe.

Ein bloß von journalctl/iptables-save zurückgegebener Nichtnull-Code würde in v1 dagegen
nur als Datenfeld aufgenommen; subprocess.run verwendete kein check=True. Das allein erklärt
Exit1 nicht. Die gepinnten Assertion-Prüfungen liegen vor dem beobachteten journalctl-Start.

**Die tatsächliche Exception bleibt unbekannt. Journal-Timeout ist weiterhin nur eine
Hypothese**, weil stderr nicht gesichert wurde. Auch ein künftiger Timeoutnachweis aus v2
würde zunächst den neuen Lauf belegen, nicht rückwirkend den fehlenden v1-Trace ersetzen.
Historische leere Ausgabe, Statusdatei und Diagnose werden weder überschrieben noch ergänzt.

## Neue Architektur und Schreibgrenze

Neue Datei: `scripts/tu1nz_spicymila_dependency_readonly_v2.py`, Version2.0.0.
SHA256 `647b74d7fb5ec8d07f6dc0e0995ff24166d01a0bf1bf5b8fcc510b2cd92e7511`.
Produktions-CLI erlaubt keine Argumente und keine abweichenden Ergebnis-/Quellpfade.

Vor der ersten Abfrage wird unter dem festen privaten Basisverzeichnis
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/`
ein neuer `collector-v2-<UTC>-<Zufallskennung>`-Laufordner angelegt. Alle Eltern werden
über O_DIRECTORY/O_NOFOLLOW geöffnet; die Basis muss0700 und root bzw. chatops zugeordnet sein.
Ein vorhandener Laufordner wird immer abgelehnt, auch wenn er leer ist. Schreibzugriffe sind
an Verzeichnisdeskriptoren gebunden. Unerwartete Dateien, Symlinks und Pfad-Escapes werden
abgelehnt. Keine vorhandenen Produktionspfade werden chmod/chown-behandelt.

Nur neue Ergebnisobjekte erhalten den Eigentümer/die Gruppe der geprüften privaten Basis,
sodass chatops die späteren bereinigten Nachweise ohne weiteren sudo-Lauf lesen kann:
Verzeichnisse0700, Dateien0600. Die atomare Veröffentlichung verwendet exklusive temporäre
Datei, flush, Datei-fsync, Rename und Verzeichnis-fsync. Signalzustellung wird während dieser
kurzen Veröffentlichung gesperrt; danach wird eine Unterbrechung normal verarbeitet.

Unabhängige Abschnitte:

1. Lauf-/Versionsmetadaten, monotone Zeiten, Python-Version und Launcher-Prüfsummenbestätigung.
2. Geschützte Dateien, systemd/Skripte und Crontabs.
3. Nginx-/Proxydateien.
4. Docker-/Cron-Journal in separat gesicherten Sieben-Tage-Zeitfenstern ab2025-10-12.
5. NAT/DNAT-Metadaten ausschließlich für8090 und8081.
6. Abschlussmanifest mit SHA256, Dateigrößen, Modi, Abschnittsstatus und COMPLETE/INCOMPLETE.

Jeder Abschnitt schreibt unmittelbar eine eigene JSON-Datei. Fehler erhalten zusätzlich
separate Fehlerdateien mit Abschnitt, monotonem Start/Ende, Rückgabecode bzw. bereinigter
Exception-Klasse, Timeoutflag und kurzer fest vorgegebener Fehlermeldung. Keine Rohfehlertexte,
Umgebungswerte, Journalnachrichten, Tokens oder Nutzinhalte werden gespeichert.
Dateiinhalte werden nur auf Prüfsumme, Rechte und Trefferpositionen reduziert.
Quell-Symlinks werden als nicht verfolgt dokumentiert; Ergebnis-Symlinks sind verboten.

Journal-stdout wird über nichtblockierende Pipes/Selektoren gestreamt. Stderr wird sofort
verworfen und nur seine Bytezahl gezählt. Pro Fenster15 Sekunden monotones Zeitlimit;
Zeilenobergrenze64KiB und maximal5000 gespeicherte Treffer. Überschreitungen markieren
unvollständige Abdeckung. Inklusive Zeitgrenzen können Randtreffer doppelt erfassen;
Fensterzähler dürfen nicht ungeprüft als eindeutige Ereigniszahl addiert werden.

Jedes Unterprogramm läuft in einer eigenen Prozessgruppe. Nach Timeout folgen TERM/KILL,
Warten auf den direkten Prozess und eine begrenzte /proc-Prüfung, dass keine ausführbaren
Prozessgruppenmitglieder verbleiben. Ein Zombie ist bereits beendet, aber noch nicht vom
zuständigen Elternprozess eingesammelt. Andere Prozessgruppen werden nicht signalisiert.
Ein Fehler/Timeout im Journal verhindert die anschließende NAT-Prüfung nicht.

SIGINT/SIGTERM und unerwartete Exceptions erzeugen ein INCOMPLETE-Teilmanifest. Bereits
veröffentlichte Artefakte werden nicht gelöscht. Ein wiederholtes Terminationssignal wird
während des Manifestabschlusses ignoriert. SIGKILL, Stromverlust oder ein nicht mehr
beschreibbares Dateisystem können technisch keine nachträgliche Manifestgarantie bieten;
die zuvor atomar gespeicherten Dateien bleiben der Wiederaufnahme-/Diagnosebestand.

Exitcodes:

| Code | Bedeutung |
|---|---|
|0|Alle geplanten Abschnitte erfolgreich, Manifest COMPLETE.|
|2|Sicherer Laufordner vorhanden, Fehler/Unterbrechung oder unvollständige Abdeckung; Teilergebnisse prüfen. Bei Speicherfehler zusätzlich Manifestexistenz prüfen.|
|3|Fatal vor sicherer Ergebniserstellung, z.B. unzulässiger Aufruf oder unsicherer Ergebnispfad.|

## Offline-Validierung

`tests/test_spicymila_dependency_readonly_v2.py`:25 Tests, abschließend alle bestanden
auf Server-Python3.12 ohne sudo. Ausschließlich kontrollierte Python-Fake-Kommandos,
synthetische Journal-/NAT-Zeilen und isolierte temporäre Verzeichnisse. Keine produktive
journalctl-/iptables-Abfrage, keine Container- oder Firewalländerung durch die Tests.

Abgedeckt: Timeout; Rückgabecode17; ungültiges JSON; fehlendes Programm; Zugriffsfehler;
2MB-Einzelzeile und5100 Datensätze; Geheimnisse in stderr, Journal, Datei und Exceptions;
SIGINT/SIGTERM in späterem Abschnitt; Signal während Rename; Setup-Exception;
Fortsetzung nach Abschnittsfehler; Erhalt früherer Ergebnisse; fsync-Reihenfolge;
Hashmanifest;0700/0600; Symlinks, Fremddateien, existierende Laufordner und Pfad-Escapes;
Beendigung einer Fake-Prozessgruppe einschließlich Kindprozess; Timeout bei Prozessbereinigung.

Ein Zwischenlauf fand eine Race Condition: SIGKILL war gesendet, ein Fake-Kind noch kurz
im ZustandR. Der Test wurde nicht abgeschwächt. Die Prozessgruppen-Nachprüfung wurde ergänzt;
die24 damaligen Tests bestanden danach dreimal, die endgültige Fassung besteht25 Tests.
Alle Zwischenprotokolle und Skriptstände bleiben privat erhalten.

Nachweispfad:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/collector-v2-validation-20260927T094954Z/`.
Freigegebener Offline-Stand: `offline-tests-approved-candidate.log`.
Eine echte privilegierte Ausführung von v2 steht ausdrücklich aus.

## Erhaltung und nächste Freigabegrenze

Produktionscontainer-IDs, Images, Config, HostConfig, Mounts, Netzwerke, Startzeiten und
Restartzähler stimmen mit der Ausgangsinventur überein. Compose-SHA256 bleibt
`04c65475baa7a55067366b78295c8fa663df7996beca04980e191dded7dc3da0`.
Alle42 Hardening-Dateien bytegleich. Detached Checkout weiterhin sauber bei
7c634d3b82572e8459d51c69f04dce82c624d766. V1 und fe2a806 unverändert erhalten.

Nach Commit/Push wird genau ein neuer sudo-Befehl privat vorbereitet: geprüfte Skriptbytes
lesen, SHA256 im selben Speicher prüfen und exakt diese Bytes ausführen; keine erneute
Dateilesung zwischen Prüfung und Ausführung. Der Befehl wird weder gezeigt noch gestartet,
bevor Daniel erneut ausdrücklich „Ich bin am MacBook bereit.“ bestätigt.
Der alte Aktivierungslauncher wird nicht verwendet. Zweck des zusätzlichen Bot-Netzwerks
bleibt ungeklärt; keine Aktivierung, keine Endpoint-/Compose-/Healthcheck-Änderung.
