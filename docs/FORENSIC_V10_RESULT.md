# V10-Root-Forensik: UNRESOLVED, keine neue Migration

Der am 28.09.2026 ausdrücklich freigegebene einzelne Leselauf ist beendet.
Vorbereitungscommit: `f3202c48596956d8d9e2259047ee96fc7e7d0002`.
Sammlung beendet um **18:13:40.063282 UTC / 20:13:40 Berliner Zeit**.
Monotone Dauer der Abschnitte: 23,157466026 Sekunden.

**Gesamtklassifikation: UNRESOLVED.** Keine neue Migration, Aktivierung,
Wartungsfrist, Recovery-Ausführung oder zusätzlicher Root-Leselauf wurde begonnen.
Der historische V9-Versuch bleibt INDETERMINATE. Alte Befehle und Launcher
werden nicht wiederverwendet. Auch V10 ist mit der verbrauchten Ergebnis-ID
kein erneut auszuführender Befehl.

## Gesicherte Ergebnisse

Root-Verzeichnis:
`/var/lib/forensic-v10-20260928-2d6c7fc1c28946afa6c8213d0c4727bb`.
Manifest-SHA-256:
`a175061911c73b127a63a175aaa6bc15d7450607ab1924f83a1e3641d83009aa`.

61 bereinigte Ergebnisdateien einschließlich Manifest wurden aus der
Terminal-Historie des eindeutig zugeordneten V10-Fensters übernommen. Keine
ungefilterte Terminal-Historie und keine Passworteingabe wurde gespeichert.
Alle 60 Einzelergebnis-Hashes stimmen mit dem Root-Manifest überein; auch dessen
Hash stimmt mit der Abschlussausgabe überein. Lokale private Kopie:
`/Users/daniel/.codex/tu1nz-recovery/forensic-v10-20260928/collected-results`.
Nur der abgeleitete Bericht wird versioniert, nicht die private Sammlung.

Sammlerstatus **INCOMPLETE**: 59 von 60 Abschnitten COMPLETE. Ein Abschnitt
`artifacts` ist unvollständig. Keine Journalabfrage hatte einen Timeout.

## Warum keine Entwarnung möglich ist

1. Die statische Aussage bleibt MUTATION_REACHABLE_BEFORE_REFUSAL: explizite
   Hostmutationen liegen hinter dem reproduzierbaren `-.mount`-Fehler;
   frühe Python-Importe konnten aber vor der Bytecode-Sperre Cachedateien
   schreiben. Die damalige Python-Binärdatei und sämtliche damaligen Caches
   besitzen keine vollständige gebundene Vorzustandsaufnahme. Aktuell gelesene
   Cache-Zeitstempel schließen historische Mutationen nicht beweiskräftig aus.
2. Das vorhandene Auditarchiv beginnt erst am **15:17:23.368 UTC**, nach der
   Root-Sitzung **15:15:18.857100–15:15:21.513139 UTC**. Diese Abdeckungslücke
   lässt sich durch einen erfolgreichen heutigen Lesebefehl nicht schließen.
3. Die älteren Archive `/var/lib/tu1nz-root-trust-v5` und
   `/var/lib/tu1nz-root-trust-v51` überschreiten jeweils die vorgesehene
   Inventurgrenze von 2.000 Einträgen. Jeweils 2.001 Metadatensätze plus
   ENTRY_BOUND-Markierung sind erhalten, keine vollständige Inventur.
4. Der Statusdetektor erfasst außerdem historische Marker mit dem Wert
   INCOMPLETE als verschachtelten Abschnittsstatus. Diese Darstellungsgrenze
   darf nicht als neuer historischer Fehler interpretiert werden. Die echten
   ENTRY_BOUND-Lücken bleiben unabhängig davon bestehen. Weder Sammler noch
   historische Ergebnisse wurden nachträglich verändert oder umklassifiziert.

Es gibt **keinen belastbaren Zuordnungsnachweis einer V9-Hoständerung**. Das ist
nicht gleichbedeutend mit NO_ROOT_MUTATION. PARTIAL_ROOT_MUTATION wird ebenfalls
nicht aus bloßen Zeitstempeln oder fremden Änderungen abgeleitet.

## Bestätigter gegenwärtiger Zustand

- V9-Root-Transaktionsverzeichnis, installierte V9-Bibliothek und Codex-Broker-
  Verzeichnis fehlen. Worker und beide Watchdog-Units sind not-found/inactive.
  Keine erfassten laufenden Prozesse referenzieren den alten Versuch.
- Altes Staging und Kapsel sind vorhanden, Eigentümer chatops, Modi 0700/0600,
  Inodes 274307/274311, ursprünglicher Kapsel-SHA unverändert. Diese Gegenwarts-
  feststellung beweist nicht, dass andere Artefakte niemals existiert haben.
- 19 von 20 an V9 gebundenen Datei-Hashes stimmen. Einzige Abweichung dieser
  Menge ist die gesondert bewertete MyChatBuddy-Unit.
- sudoers-Include-Kette wurde erfasst; `visudo -c` endet mit 0. Die drei
  gebundenen sudoers-Dateien sind bytegleich. Die vorgeschlagene neue
  `90-tu1nz-codex-ops`-Datei fehlt. Effektive Regeln sind bereinigt und
  hashgebunden dokumentiert; die Sammlung legt keine neuen Rechte an.
- chatops-Gruppen: 1001, 4, 27, 100, 999, 987. Docker-Mitgliedschaft besteht
  weiterhin. Socket: Device 25, Inode 1268, root:docker (GID 987), 0660, keine
  ACL-Xattrs. Kein neuer Docker-Socket-Drop-in; geladene Socket-Unit bestätigt
  root:docker/0660. Im zeitpunktbezogenen FD-Snapshot sind Listener-FDs PID 1
  und dockerd zugeordnet; keine dauerhafte Aussage über sämtliche Verbindungen.
- Root-Dokumentationsdateien, acht Trendwatch-Units, Trendwatch-Skript,
  Backup-Notify-Skript, `tu1nz-bot.service`, Agentmode- und Telegram-Unit
  entsprechen ihren gebundenen Hashes. Keine Quarantäneänderung vorgenommen.
- nftables wurde erfolgreich gelesen. INPUT und FORWARD stehen sowohl bei IPv4
  als auch IPv6 auf DROP. Das allein ist kein vollständiger bytegleicher
  Vorher-/Nachher-Nachweis aller dynamischen Firewallregeln.
- Effektives OpenSSH: Port 2222, IPv4-Listenadresse 0.0.0.0:2222,
  AllowUsers chatops, PermitRootLogin no, PasswordAuthentication no,
  PubkeyAuthentication yes. Keine Änderung durch diesen Lauf.
- Fail2ban-Jail sshd ist abfragbar und verwendet die nftables-Aktion auf
  **2222**. Dienst ist aktiv. Keine Regel oder Sperre wurde geändert.
- Alle 14 noch vorhandenen Container stimmen bei ID, Image, Startzeit, PID,
  Neustartzähler, Config, HostConfig, Mounts und Netzwerkendpoints mit der
  kanonischen V9-Baseline überein. Fehlender Healthcheck wird fachlich identisch
  als `none` eingeordnet (V10 liefert dafür JSON null); kein Healthtest gelockert.
  cAdvisor und api-mychatbuddy healthy; spicymila_bot und bekannter Legacy-
  Trendwatch-Container weiterhin unhealthy. Keine Containerbefehle ausgeführt.
- Agentmode, Telegram, öffentliche erfasste Dienste, Docker, Tailscale, SSH
  und Fail2ban zeigen in den vergleichbaren erfassten Status-/PID-Feldern keine
  Abweichung. Es wurden keine aktiven Website-, Proxy- oder Monitoringprobes
  ausgelöst; ein neuer Ende-zu-Ende-Funktionstest wird nicht behauptet.

## MyChatBuddy: fremde Änderung getrennt bewertet

**FOREIGN_CHANGE_SEMANTICS_KNOWN_ACTOR_UNKNOWN.** Der Root-Lauf bestätigt den
vorab bekannten semantischen Diff und den Hash der aktuellen Unit:
`e9f6b2e0fddb430673843b628cdde9e7d472979480e04a7753c365de8c45c976`.
Sie entspricht dem verwalteten Unit-Artefakt im getrennt fortgeschriebenen
Checkout `9b383960291da469671c3888cfa4fdcc3c33cf01` (PR #63).

Ergänzt wurden RestartForceExitStatus=75, RestartSec=185s,
StartLimitIntervalSec=15min, StartLimitBurst=3, StartLimitAction=none und
Dokumentationsreferenzen. Keine Drop-ins, root:root/0644, keine ACL-Xattrs.
Geladener Zustand: inactive/dead, disabled, MainPID 0, NeedDaemonReload=no.
Der ursprüngliche Container `mychatbuddy-private-alpha` fehlt weiterhin.

Die Journalbelege bestätigen:

- Exit 75 am **01:12:34.356467 UTC**, deutlich vor dem alten Root-Aufruf.
- Hashgebundener alter sudo-Python-Aufruf am **15:15:18.855377 UTC**, Root-Sitzung
  15:15:18.857100 bis 15:15:21.513139 UTC.
- daemon-reload-Ereignisse 15:24:52–15:24:53, 15:46:58–15:47:00 und
  17:21:42–17:21:44 UTC.
- MyChatBuddy-Start-/Stop-Meldungen um **15:46:57–15:46:58 UTC**. Diese späteren
  Aktivitäten werden ausdrücklich nicht dem V9-Fehlversuch oder dem V10-Lauf
  zugeschrieben. V10 wurde erst um 18:13 UTC ausgeführt.

Die Sammlung enthält einen Audit-PATH-Hinweis auf die Unit nach dem alten
Root-Aufruf, aber keinen ausreichenden Akteursnachweis. Weder Unit-mtime,
Git-Reflog noch diese Einzelzeile begründen eine Personenzuschreibung.
MyChatBuddy wurde von diesem Arbeitsstrang nicht gestartet, gestoppt oder
zurückgesetzt. Keine fremde Änderung wurde rückgängig gemacht.

## Gesperrte Folgeschritte

Keine neue Migrationsvorbereitung, keine Aktivierung, kein PR. Bestehende
Nachweise unangetastet aufbewahren. Nicht blind den alten Zustand restaurieren:
Die MyChatBuddy-Änderung ist eine getrennte Versions-/Betriebsänderung.

Ein weiterer Vorschlag müsste die Beweisgrenzen ausdrücklich behandeln:
vorhandene ältere Archive gezielt und vollständig offline zuordnen, verfügbare
historische Interpreter-/Cache-Nachweise suchen und die unbekannte historische
Abdeckung ehrlich beibehalten. Ein neuer Root-Lauf oder eine Lockerung der
NO_ROOT_MUTATION-Anforderungen wird hier weder vorausgesetzt noch ausgeführt.
