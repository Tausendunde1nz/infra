# V10: ausschließlich lesende Root-Forensik, noch nicht ausgeführt

Basis: `42a92dacc5495ef32e47a59ea738ecdc8b3374cd`, Branch
`security/codex-privileged-ops-2026-09-27`. Dieser additive Stand bereitet genau
einen Leselauf vor. Er ist keine Migrationsvorbereitung oder Aktivierungsfreigabe.
V9 bleibt **INDETERMINATE**; alter Befehl, Launcher, Kapsel und Verzeichnis sind
unverändert und dürfen nicht wiederverwendet werden. Kein PR, Watchdog,
Zeitfenster, sudo-Lauf oder Eingriff in MyChatBuddy wurde hier ausgelöst.

## Beweisstand und Kontrollfluss

`control_flow_evidence.json` bindet die alte Kapsel
`865b33e81db52f497fe834293619ef933f1bfa38ab80b715e91b51c98c342690`
und sämtliche eingebetteten Module. `historical_bootstrap_fixture.json` enthält
unveränderte, separat gehashte Bootstrap-Quellbytes. Der Test führt nur diese
Funktion mit vollständig gefälschten Betriebssystem-/Datei-/Prozessadaptern aus.
Er führt niemals den historischen Launcher oder die Kapsel aus.

Reihenfolge im historischen Bootstrap:

1. Root-Prüfung, prozesslokale Umask und Arbeitsverzeichnis.
2. Payload-Schema, Modulprüfsummen und Syntaxprüfung.
3. Abwesenheit bereits bestehender Transaktionsverzeichnisse und Units.
4. Geladene Units auflisten; `NeedDaemonReload` jeder Unit abfragen.
5. Erst danach Originaldateien lesen, Baselines vergleichen und Kandidaten bilden.
6. Erst danach Verzeichnisse, Dateien, Lock, Sicherungen, Units und Watchdog-
   Definitionen erzeugen; anschließend daemon-reload, Transaktion und Worker.

Die historische Abfrage für `-.mount` übergibt den Namen vor dem Optionsende.
Der belegte Reproduktionsfehler ist Exit 1 / ungültige Option `.`. `checked`
wirft `Refused`; in dieser Schleife gibt es weder Catch noch Finally.
Der äußere Handler meldet die Klasse und beendet mit 70. Der spätere
Store-Finally ist von diesem Fehlerpunkt nicht erreichbar. Die damals lediglich
protokollierte Exception-Klasse beweist allerdings nicht allein, welche der
mehreren Refused-Stellen tatsächlich ausgelöst wurde.

**Maschinenklassifikation: MUTATION_REACHABLE_BEFORE_REFUSAL.** Die expliziten
Hostmutationen liegen hinter der fehlerhaften Abfrage. Der alte Aufruf
`python3 -I -S` und die frühen Standardbibliotheksimporte erlauben jedoch
Bytecode-Cache-Schreibvorgänge, bevor `sys.dont_write_bytecode=True` gesetzt ist.
Das ist eine erreichbare mögliche Nebenwirkung, kein Nachweis, dass sie damals
stattfand. Die damalige Interpreter-Binärdatei ist nicht historisch hashgebunden.
Das aktuelle Server-Python 3.12.3 meldet ohne `-B` False; Apples Python 3.9 meldet
True. Der portable positive Fixturetest aktiviert deshalb ausschließlich in
seinem temporären Testverzeichnis ausdrücklich die schreibende Cache-Variante;
der separate Negativtest prüft den neuen `-B`-Start ohne diese Umschaltung.

Alle neuen systemd-Aufrufe werden über einen auf lesende Verben begrenzten
Builder gebildet: Optionen, Verb, `--`, danach unveränderte Unit-Argumente.
Keine Shellauswertung. Historische Dateien werden dafür nicht umgeschrieben.

## Neue, begrenzte Sammlung

Transaktion: `forensic-v10-20260928-2d6c7fc1c28946afa6c8213d0c4727bb`.
Einziges Schreibziel des Root-Sammlers:
`/var/lib/forensic-v10-20260928-2d6c7fc1c28946afa6c8213d0c4727bb`.
Vorhandenes Ziel, Symlink, fremde Ergebnisdatei oder unsichere Elternrechte
führen zum Abbruch. Verzeichnis 0700, Dateien 0600; kein chown bestehender Pfade.
Atomare Veröffentlichung mit temporärer Datei, fsync und rename. Manifest wird
nach jedem Abschnitt aktualisiert und bindet die Ergebnisdateien per SHA-256.
Der Launcher liest einmal die durch SHA-256 gebundenen Skriptbytes in den
Speicher; genau diese Bytes werden interpretiert. Schon der erste Interpreter
startet mit `-I -S -B`. Kein Root-Import aus dem schreibbaren Worktree.

Unabhängige Abschnitte erfassen Metadaten/ACL-Xattrs und Prüfsummen der alten
Artefakte, feste Markerfelder, sudoers-Include-Kette, visudo, effektive sudo-
Regeln, Gruppen, Prozessgruppen, Docker-Socket und FD-Zuordnung, Drop-ins,
gebundene Dateien, Units, Container-Inspect, nftables, UFW, sshd, Fail2ban,
Auditabdeckung, stundenweise Journalfenster und MyChatBuddy-Unitsemantik.
Fehler einer Unit beseitigen keine anderen Ergebnisse. Laufende Prozesse und
Sockets sind ausdrücklich nicht atomare Momentaufnahmen; unlesbare oder
unzugeordnete Daten bleiben als Lücke sichtbar.

Kein docker exec, kein Healthcheck, kein HTTP-Aufruf, kein Start/Stop/Restart,
kein daemon-reload, kein systemd-run, keine Gruppen-, Socket-, Firewall- oder
sudoers-Änderung. Reguläre direkt gelesene Beweisdateien werden mit O_NOATIME
geöffnet, soweit die Plattform dies anbietet. Übliche Kernel-Zugriffsmetadaten
und systemeigene Audit-/sudo-Protokollierung werden nicht manipuliert oder als
von einem lesenden Lauf vollständig vermeidbar dargestellt.

Rückgabecodes: 0 = COMPLETE, 2 = INCOMPLETE mit erhaltenen Ergebnissen,
70 = FAILED vor regulärem Lauf. stdout, stderr, Rückgabecode, Timeout und
monotone Zeiten bleiben getrennte Felder. stderr wird ausschließlich als
Länge, Hash und feste Fehlerkategorien gespeichert. Journalnachrichten,
Environment-Werte, Credentials, vollständige Docker-Umgebungen und rohe
sudo-/Audit-Befehlsargumente werden weder gespeichert noch ausgegeben.
Unitwerte außerhalb enger sicherer Felder werden nur gehasht; Exec-Zeilen
liefern Programmname und Argumentzahl. Das ist bewusst keine Rohkopie geheimer
Unit-/Environment-Inhalte. Unbekannte Semantik bleibt ungeklärt.

Journalfenster haben jeweils 30 Sekunden Timeout; stdout wird streamend und
begrenzt verarbeitet. Auch bei frühem Ende des Elternprozesses wird seine
separate Prozessgruppe bereinigt. Vorherige Abschnitte bleiben bei Timeout,
SIGINT, SIGTERM oder Exception bestehen. Bei normalen Abschnittsfehlern werden
auch spätere Abschnitte gesammelt. Fensterbegrenzungen werden als Lücke markiert.

Am normalen Laufende wird zusätzlich ein gzip/base64-kodiertes Bündel der
bereits bereinigten Ergebnisse über den SSH-stdout-Kanal ausgegeben. Jeder
Datensatz behält seinen Hash. Damit kann die Auswertung ohne zweiten sudo-Lauf
und ohne Lockerung der Root-Verzeichnisrechte erfolgen. Diese Ausgabe ist
weiterhin privat zu behandeln und nicht als Rohbeweissammlung zu committen.
Bei einem Fehler der Ausgabe bleiben die Root-Dateien erhalten.

## MyChatBuddy und fremder Checkout-Stand

Vorherige Unit: SHA-256
`53a2fad8675a6cfa79196d2fea64e56745403cdc4802ae93cb32682c13d71d26`.
Aktuelle Unit beim nicht privilegierten Vorabvergleich: SHA-256
`e9f6b2e0fddb430673843b628cdde9e7d472979480e04a7753c365de8c45c976`.
Sie entspricht bytegenau `managed/systemd/mychatbuddy-private-alpha.service`
im sauberen detached Checkout `9b383960291da469671c3888cfa4fdcc3c33cf01`.
Dieser Commit enthält PR #63, `fix/mychatbuddy-rc5-exit75-recovery-v1`.
Das ist Versionsprovenienz, kein Beweis der ausführenden Person.

Semantische Änderungen: `RestartForceExitStatus=75`, `RestartSec=185s`,
`StartLimitAction=none`, `StartLimitBurst=3`, `StartLimitIntervalSec=15min`
und Dokumentationsreferenzen. Keine übrigen Direktivenänderungen im Vergleich.
Vorläufig: **FOREIGN_CHANGE_SEMANTICS_KNOWN_ACTOR_UNKNOWN**.
Die neue Sammlung überprüft aktuelle Unit und Drop-ins erneut; unbekannte
weitere Direktivenänderungen führen zu FOREIGN_CHANGE_UNRESOLVED.

Der zuvor beobachtete Exit 75 am 28.09.2026 um 01:12:34 UTC liegt vor der
bekannten V9-Root-Sitzung um 15:15:18.857100 UTC. Der neue Sammler muss die
Journalbelege dafür erneut erfassen. Die Unit-Metadatenänderung um 15:24:51 UTC
beweist keinen Akteur. MyChatBuddy wird weder gestartet noch zurückgesetzt.

Der detached Checkout wurde in diesem Arbeitsstrang nicht verändert.
Sein Reflog verzeichnet gegenüber dem alten Snapshot `18080ac...` Übergänge
um 13:43:40 und 14:40:04 UTC auf `f1c3b9a...` und `9b383960...`.
Der Pfad-Diff umfasst 600 Löschungen, 2 Änderungen, 167 Ergänzungen und
1 unveränderte Umbenennung; Hash der vollständigen name-status-Ausgabe:
`12f5bfaf66e37ee767754347f8c6d1d4b8079bf91cfbc640360cf86b90888000`.
Dies wird nicht repariert oder mit unserem Branch vermischt. Die Behauptung,
der gesamte Live-Zustand sei noch identisch mit dem alten Snapshot, wäre falsch.

## Offlinevalidierung und Erhaltung

Die neuen Tests decken Optionsgrenzen, alle geforderten Unitformen, fehlende
Units, leere und mehrere Namen, Shellzeichen, Timeout, Prozessfehler,
Parserfehler, fehlendes Programm, Ausgabegrenzen, Teilergebnis-Erhalt,
Unterbrechung, Ergebnisrechte, atomare Veröffentlichung, Hashprüfung,
Quell-Manipulation, Symlinks, Root-/Argumentgrenzen, Geheimnisunterdrückung,
Markerfelder, semantischen Unitvergleich und Bytecode-Verhalten ab.
Testzahlen und endgültige Quellhashes stehen in `FORENSIC_V10_PREPARATION.json`.

Erneut bestanden: unveränderte V9-Suite (130 Tests), bisherige Privilegien-
Suiten (457 Tests), neue Tests lokal auf Python 3.9 und auf Server-Python 3.12.
Die 42 Hardening-Dateien, 701 gebundenen Vor-V9-Repository-Dateien, 30 V9-
Quellen und 1.125 privaten V3-Nachweise wurden bytegleich geprüft.
`1cf0d79` bleibt Vorfahr. Altes Staging: Verzeichnis-Inode 274307/0700,
Kapsel-Inode 274311/0600 und ursprünglicher SHA unverändert.
Private Sicherungen, alte Kapsel und rohe Live-Daten werden nicht committed.

## Freigabegrenze und weitere Auswertung

Vor dem einzigen Root-Leselauf ist einmal erneut „Ich bin am MacBook bereit“
erforderlich. `run_v10.command` führt genau einen sudo-Aufruf über bestehendes
Tailscale-IPv4/SSH-2222 aus; zwei In-Memory-Prüfsummen binden Launcher und
Sammler. Noch nicht ausgeführt. Kein erneuter alter Befehl.

Nach dem Lauf: Manifest/Hashkette, Vollständigkeit, Kontrollfluss, gebundener
Sicherheitsvorzustand, mögliche Root-Artefakte und fremde Änderung gemeinsam
bewerten. Der Sammler meldet vorsorglich UNRESOLVED und gewährt niemals allein
wegen fehlender Dateien NO_ROOT_MUTATION. PARTIAL_ROOT_MUTATION verlangt einen
belastbaren Zuordnungsnachweis; dann nur Recoveryplan, keine Ausführung.
NO_ROOT_MUTATION verlangt sämtliche vom Auftrag definierten Voraussetzungen.
Insbesondere sind die mögliche frühe Interpreter-Nebenwirkung und fehlende
historische Beweise derzeit offen. Bis zur Klärung keine neue Migration.
