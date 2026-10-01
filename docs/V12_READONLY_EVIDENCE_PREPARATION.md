# V12 – ein lesender Root-Nachweis für V11

Basis `63a17cfd6c74ade3bb1ed36419c77158915db976`, 01.10.2026.
Branch `security/codex-privileged-ops-2026-09-27`.
Governance: `GOVERNANCE_V1_1_ACTIVE`. Keine historische Archivsuche, PDFs oder
Doku.zip. Kein Root-Lauf, keine Live-Aktivierung und kein Watchdog in dieser
Vorbereitung. Der Lauf benötigt Daniels erneute aktuelle MacBook-Bereitschaft.

## Ausschließlicher Umfang

1. Mommyramonas aktuelle Netzwerkidentität aus einem festen Docker-GET,
   Abgleich von Container-ID, Image und Netzwerknamen sowie Kontinuität am Ende.
2. Die n8n-Tabelle `workflow_entity`: technische ID, Aktivstatus und ausschließlich
   erkannte Netzwerkbezüge in Node-Parametern; keine Workflow-/Namen-/Credential-
   Ausgabe. Ergänzend die bereits benannte geschützte Nginx-Datei
   `/etc/nginx/sites-enabled/tu1nz.conf`, ausschließlich Zeilennummer/Bezug/Hash.
3. Struktur der Regeln für Hostport 8081 bzw. die aktuellen Mommyramona-Adressen:
   nftables und iptables/ip6tables einschließlich relevanter Sprungpfade,
   Hooks, Prioritäten, Tabellen, Chains und Reihenfolge. Nicht passende Regeln
   werden als ausgelassene Positionen gekennzeichnet. Keine Firewalländerung.
4. Docker-Publishing, Firewalloptionen aus `daemon.json` und den einschlägigen
   Argumenten des nach systemd identifizierten dockerd-Prozesses, iptables-
   Backendversion, Docker-Version und passive Listenerprüfung ausschließlich
   Port 8081. Kein öffentlicher Verbindungstest.
5. Der unveränderte vorbereitete AppArmor-Sammler ist vollständig eingebettet
   und separat auf SHA-256 gebunden. Keine Policykompilierung oder -änderung.
   Freitext der Policyquelle/Features wird vor dem Speichern entfernt; Hashes,
   ABI-/Dateimetadaten, Profilzuordnung und Enforce-Zustand bleiben erhalten.

Der Scope enthält weder Container-Exec/Recreate noch Connect/Disconnect, keine
Dienständerung, keine Datenbankschreiboperation, keine systemd-Unit/Timer-
Anlage, keine Brokerinstallation und keine Migration.

## n8n ohne Rohdatenkopie

DB und WAL werden mit O_RDONLY/O_NOFOLLOW, Typ-/Eigentümer-/Größenkontrolle und
zweifachem Metadaten-/SHA-Vergleich ausschließlich in RAM gelesen. Bei laufenden
Schreibvorgängen höchstens drei neue konsistente Leseversuche. Kein SQLite-Open
auf dem produktiven Pfad, keine Lock-/SHM-/Journal-Erzeugung dort und keine
Dateikopie von DB, WAL, Workflowinhalten, Credentials oder Umgebungsdateien.

Die WAL-Header-, Salt- und Frame-Prüfsummen werden validiert; ausschließlich bis
zum letzten Commit gehörende Frames fließen in den RAM-Snapshot ein. SQLite
öffnet nur `:memory:` und deserialisiert diesen Snapshot. Feste SELECTs,
query_only, trusted_schema=OFF und deaktivierte Extensions. Es werden keine
Expressions ausgeführt und keine Credentials entschlüsselt. Ungültige Daten
werden nicht als »kein Treffer« behandelt.

Treffer enthalten nur Datensatz-ID, Node-Index, technischen Parameterordinal,
Aktivstatus, Referenztyp und den bereits bekannten Netzwerkbezug. Eine aktive
Konfiguration beweist keine tatsächliche Nutzung. Dynamische Ausdrücke und
Credential-Verweise bleiben ausdrücklich als ungeklärte Indirektionen sichtbar.

## NAT-Interpretation

Zähler werden aus Strukturhashes entfernt. Regelkommentare werden aus
Geheimnisschutzgründen ausschließlich als SHA-256 gespeichert. Ziel-IP/-port,
Protokoll, relevante Chains/Sprünge und Reihenfolge bleiben auswertbar.
Docker-/UFW-Chainnamen ergeben eine strukturelle Zuordnung, keinen Beweis über
historische manuelle Bearbeiter. Unbekannte/andere Regeln bleiben unzugeordnet.
Docker-Publishing und Backenddaten müssen mit der effektiven Regel übereinstimmen.

Die automatische Hostport-Anpassung bei neuer IP/MAC wurde bereits in den
isolierten V11-Tests nachgewiesen. V12 führt keine produktive Neuerstellung aus.
IPv6 wird separat erfasst: fehlendes IPv6-DNAT schließt einen docker-proxy-
Listener nicht aus. Eine fehlende Regel oder ein unbekanntes Backend wird nicht
als bereits gelöste Netzwerkentscheidung ausgegeben.

## Vertrauensgrenze und ein einziger sudo-Aufruf

`command_v12.py` rendert genau eine SSH-Verbindung über Tailscale-Port 2222 mit
festem bestätigtem Hostkey und genau einen sudo-Aufruf. Die Shell übergibt den
geprüften Bootstrap als festes Inline-Programm an `/usr/bin/python3 -I -B -c`;
kein Root-Import und keine Root-Ausführung der Worktree-Datei.

Der Bootstrap prüft die root-eigenen Eltern `/`, `/var`, `/var/lib`, erzeugt
ein neues `/var/lib/tu1nz-evidence-v12-<Zufalls-ID>` und darin `staging` 0700.
Er öffnet ausschließlich den fest vorgegebenen Collectorpfad mit O_NOFOLLOW,
prüft Typ, Links, Eigentümer 1001 und stabile Metadaten und kopiert die Bytes in
eine neue root-eigene Datei 0600. **Die erwartete SHA-256 wird an dieser Kopie
nach fsync geprüft.** Erst dann execve von Root-Python `-I -B` mit festem
Environment und PYTHONDONTWRITEBYTECODE=1. Die ursprüngliche Quelle wird nicht
nochmals zur Ausführung geöffnet. Verzeichnisse und Kopie mit ACLs werden verweigert.

Bootstrap-Start, verifizierte Kopie oder Abbruch vor Ausführung werden in neuen
atomaren privaten Markern festgehalten. Vorhandene Verzeichnisse/Dateien werden
nicht wiederverwendet oder überschrieben. Kein alter Launcher ist beteiligt.

Private Abschnittsergebnisse liegen root:root 0600 unter `private` 0700.
Nur die bereits reduzierten, geheimnisfreien Ergebnisse werden unter `public`
0755 als root:root 0644 veröffentlicht; das neue äußere Verzeichnis ist 0711.
Es werden keine unredigierten n8n-/NAT-/Env-Rohinhalte persistiert. Auch private
Ergebnisse enthalten nur den begrenzten Befund. Bootstrapmarker bleiben 0600.

Jeder Abschnitt wird sofort atomar/fsync/no-clobber gespeichert. Fehler führen
zu geheimnisbereinigter Fehlerklasse/-kennung und INCOMPLETE; spätere Abschnitte
werden soweit möglich trotzdem gelesen. SIGINT/SIGTERM erhalten vorangegangene
Ergebnisse und erzeugen ein Teilmanifest. Keine Roh-Exceptions oder stderr-
Inhalte in den Ergebnissen. Kommando-Timeouts beenden die gesamte neue
Prozessgruppe. Manifest mit Artefakt-SHA-256 und monotonen Abschnittszeiten.

Exitcodes: 0 = vollständiger Leselauf, 2 = unvollständig/Abschnittsfehler,
3 = Bootstrap verweigert vor Ausführung. COMPLETE ist eine Aussage über die
Sammlung, **keine** V11-Migrationsfreigabe. Indirektionen können trotz COMPLETE
ungeklärt bleiben. Keine automatische Wiederholung eines Root-Laufs.

## Offline-Prüfungen und spätere Auswertung

Tests umfassen Root-Kopie, falschen Hash/Owner, Symlinks/Hardlinks, ACL,
TOCTOU, neue/fremde Dateien, falschen festen Quellpfad, Unterbrechung,
Manifest-/Modusprüfung, Abbruchnachweis, Kommando-Timeout/-Fehler/-Limit,
WAL mit echten SQLite-Commits und beschädigten Frames, JSON-Fehler,
Geheimnisunterdrückung, nicht ausgeführte Expressions, NAT-Sprünge,
Regelreihenfolge, IPv4/IPv6, Zählernormalisierung und AppArmor-Quellbindung.
Mac: Linux-ACL-Funktionen werden nur im Test simuliert; der echte ACL-Test läuft
auf dem Server ohne sudo in einem isolierten Verzeichnis.

Nach dem einmaligen, ausdrücklich freigegebenen Leselauf: Manifest/Dateihashes
und Privilegiengrenzen prüfen, Beobachtungen klassifizieren, aktuelle manuelle
und Docker-konsistente Regeln unterscheiden, funktionalen Netzwerkvertrag
abschließen bzw. belegte Restfragen benennen. Danach V11 und Rollback offline
vervollständigen. Keine neue »Fertig«- oder allgemeine Freigabe dazwischen.
Eine spätere Live-Aktivierung verlangt getrennte vollständige Vorbereitung und
neue aktuelle MacBook-Bereitschaft.

Keine Live-Konfiguration braucht einen Rollback: V12 schreibt nur seine neuen
privaten/redigierten Nachweise. Diese bleiben beim Fehler erhalten. Kein
automatisches Löschen alter Nachweise oder Wiederverwenden alter Befehle.

## Abschluss der Vorbereitung – 2026-10-01

53 V12-Tests auf Linux einschließlich echter ACL-Vererbung bestanden; 70
bestehende V11-Tests bestanden. Alle 108 Workflow-Schritte im isolierten
Checkout mit Rückgabecode 0. Schritt 100: zwei bestehende optionale Tests wegen
fehlender gepaarter Application-Checkouts übersprungen, nicht als bestanden gezählt.

Privater Testnachweis:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/v12-evidence-workflow-20261001T160705Z-9cc73629/results.json`
SHA-256: `f781e274c300bf9c22be0c49bae2cd1600b907dbb1d8ed729091698b393196c6`.

Alle 701 historischen Repository-Dateien, 42 Hardening-Dateien, 1125 privaten
historischen Nachweisdateien und 30 V9-Quellen stimmen mit ihren bestehenden
Hashmanifesten überein. Integrationsstand `1cf0d79` weiterhin Vorfahr.
Detached Checkout unverändert und sauber bei
`9b383960291da469671c3888cfa4fdcc3c33cf01`.

Nur sechs neue Vorbereitungsdateien werden versioniert. Keine Root-Ausführung,
keine Produktionsänderung, kein PR und keine Aktivierung. Die beiden geschützten
Sachnachweise bleiben bis zum späteren Leselauf offen. Die vollständige
V11-Transaktion ist damit noch nicht aktivierungsbereit.
