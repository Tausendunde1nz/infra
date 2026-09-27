# Root-only Docker V9 — vorbereitete gemeinsame Transaktion

Stand: 2026-09-27. Basis `9302309fdec1fd49a9c050ba8d46b703de281cef`, Branch `security/codex-privileged-ops-2026-09-27`. Ausschließlich neue Vorbereitung; keine Live-Aktivierung, kein PR, kein laufender Watchdog. Alte V3–V8-Quellen und Nachweise bleiben historisch unverändert.

## Architektur und bestätigte Erzeugungskette

Docker 28.5.1 läuft mit `/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock`. Die aktive, aktivierte Vendor-Unit `/usr/lib/systemd/system/docker.socket` erzeugt `/run/docker.sock`; keine Drop-ins, kein `/etc/docker/daemon.json`. `/var/run/docker.sock` bezeichnet denselben Socket. Beobachtete Dateisystemidentität: dev25/inode1268, root:docker, GID987, 0660. Kernel-Socket-IDs aus `ss` sind andere Identitäten und werden ausdrücklich nicht mit dem Dateisystem-Inode verwechselt.

Ein einziges neues Drop-in setzt SocketUser=root, SocketGroup=root, SocketMode=0600. Es wird weder Docker noch docker.socket neu gestartet. Die Moby-Implementierung übernimmt bei fd:// den vorhandenen systemd-FD; sie legt keinen konkurrierenden Unix-Socket an. Neustart- und Bootpersistenz wurden anhand dieser Erzeugungskette und der Drop-in-Auflösung simuliert, **nicht durch einen echten Neustart nachgewiesen**. Beim späteren Preflight werden sämtliche Erzeugerparameter erneut geprüft. Quellen: [Moby v28.5.1](https://raw.githubusercontent.com/moby/moby/v28.5.1/daemon/listeners/listeners_linux.go), [systemd 255 service semantics](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.service.xml).

Die Metadatenumstellung ist keine atomare gemeinsame chown/chmod-Systemoperation: Der geöffnete O_PATH-FD bindet den vorhandenen Inode; zuerst entzieht chmod0600 die Gruppenrechte, danach folgt chown0:0. Zwischenzustand und Schreibabsicht sind journalisiert. Die Reihenfolge öffnet keine zusätzliche Autorität.

## Dienste und MyChatBuddy

Agentmode und öffentliche Telegram-Dienste werden nicht neu gestartet. Der gelesene Agentmode-Einstieg führt Git-/Dokumentations-, Status- und Benachrichtigungsarbeit aus, keine Dockeroperation. Die direkten Einstiegspunkte der erreichbaren chatops-Units enthielten keine Dockerreferenz. Diese Prüfung wird nicht als Beweis für jede transitive Python-Abhängigkeit ausgegeben. Laufzeitidentitäten und bestehende Containerzustände sind zusätzlich verpflichtende Transaktionsprüfungen.

MyChatBuddy bleibt während der Migration unverändert laufend: bestätigter Container `03fa3d34f799c606fae2e12a5482f816d98ed22b303090a076bffcd05ae9ad4e`, Image `sha256:cda7116fc1e48ce35fb537dac8e447cf60b6bbd0c98db2b82e9c96f2809f422f`, UID/GID10001, RestartCount0. Das vorhandene Netzwerk, die sechs Mounts, ReadOnlyRootfs, CapDropALL, NNP, fehlende Portveröffentlichung und Ressourcenlimits bleiben fest gebunden.

Die Unit ändert genau vier Zeilen: leere SupplementaryGroups sowie festes `check`, `run`, `stop` des Root-Lifecycle-Helpers. Die drei neuen Exec-Anweisungen verwenden `!`: Root-Credentials, aber Beibehaltung der bisherigen Dateisystem-Sandbox. Beim späteren natürlichen Stop gilt der neu geladene ExecStop auch für den bereits laufenden Hauptprozess; er prüft den vorhandenen Containervertrag und stoppt ausschließlich diesen Namen mit festem Timeout. Der angehängte Docker-CLI-Prozess bleibt als Startmodell erhalten. Nach Normalisierung auf den Image-Digest sind die bisherigen Startargumente identisch. Kein Start/Stop wird zur Installation oder Validierung ausgelöst. Broker-Lifecycle-Aufrufe sind bis zum vollständig abgeschlossenen Migrationszustand gesperrt.

Die Datenverzeichnis-Elterneigentümerschaft wird nicht stillschweigend geändert. Bestehende Datenintegritätsfragen sind kein Anlass, Agentmode-/Anwendungszustände oder Mounts in diesem Auftrag zu migrieren. Der feste Helper erlaubt keine anderen Mounts, Images, Netzwerke, Argumente oder Environment-Programme; die Root-Environmentdatei ist hashgebunden und wird ausschließlich intern als Daten ausgewertet.

## Privilegien- und FD-Vertrag

Vor und nach der Socketumstellung werden verbundene Unix-Endpunkte, Listener, alle sichtbaren Task-FD-Tabellen, PID/Startzeit, UID/GID, Gruppen, Namespace, Root-Verzeichnis und cgroup erfasst. Unbekannte oder nicht vollständig zuordenbare Clients verweigern die Fortsetzung. Nur kurzlebige chatops-Docker-CLI-Verbindungen und reine Topologieänderungen erhalten einen begrenzten erneuten Scan; keine Prozesse werden abgeschossen. Root-Daemon, PID1-Socketaktivator, exakt gebundener cAdvisor und der unabhängige alte MyChatBuddy-CLI-Kontext werden getrennt klassifiziert. Auch chatops-O_PATH-Handles auf den Socket werden abgewiesen.

Die frühere unprivilegierte FD-Sicht war unvollständig und ist **kein** Nachweis offener bzw. geschlossener Root-FDs. Die erforderliche privilegierte Vollsicht gehört ausschließlich zum gebündelten späteren Preflight; kein weiterer separater Sammler wird gestartet.

Die alte GID987 darf in laufenden Prozessen bleiben. Ein neuer chatops-Prozess muss EACCES erhalten; die vorhandenen Task-Kontexte werden über fest eingebauten Probe-Code mit ihren Credentials, Mount-/Netzwerk-Namespaces und Root-Verzeichnissen geprüft. Es wird kein Interpreter aus einem fremden Namespace ausgeführt. Zusätzliche durch GID987 zugängliche Schreibschnittstellen werden über DAC/ACL-Prüfung der erreichbaren Pfade und Namespace-Sichten gesucht. Zusätzliche Rechte, unvollständige Sicht, Capability-Kontexte oder nicht unterstützte User-Namespaces führen zum Abbruch. Kein Default-ACL wird entfernt.

Der Endzustandsgraph betrifft die festgelegten Autoritätswege dieser Migration: Docker-Socket/GID, fünf alte sudo-Freigaben, fester Broker, MyChatBuddy-Lifecycle und bestätigte Quarantänepfade. Er erklärt nicht die 13.251 historischen Literal-Kanten pauschal für semantisch geklärt. Daniels ausdrücklich ausgenommene persönliche Rechte und Polkit werden nicht verändert. Passwortpflichtige sonstige sudo-Rechte sind nicht mit den fünf entfernten NOPASSWD-Freigaben gleichzusetzen.

## Komponenten und feste Änderungen

Neue Quellen unter `scripts/root_only_v9/`; keine Modulimporte aus einem chatops-kontrollierten Verzeichnis bei Root-Ausführung. Der spätere Root-Einstieg liest die freigegebenen Kapselbytes einmal, prüft ihren SHA-256 und interpretiert ausschließlich diese Speicherbytes unter Python `-I -S`. Installierte Module und Manifest liegen root-eigen unter `/usr/local/libexec/tu1nz-root-only-v9`; Root-Evidenz und Checkpoints unter `/var/lib/tu1nz-root-only-v9`, Broker-Evidenz unter `/var/lib/tu1nz-codex-ops`. Verzeichnisse0700, private Dateien0600; ausführbare feste Helper0755, sudoers0440. Fehlendes `/usr/local/libexec` wird ausschließlich als root:root0755 angelegt. Fremde bestehende Installationen werden abgewiesen.

Feste Änderungen: zwei Helper, eine MyChatBuddy-Unit, ein Docker-Socket-Drop-in, `/etc/group` und `/etc/gshadow` ausschließlich für chatops in docker, exakt fünf bestehende sudo-Freigaben und eine feste neue Broker-sudoers-Datei. Keine freien Root-Befehle oder Parameter. Die temporäre `migration-confirm`-Operation bestätigt ausschließlich die aktuelle Phase; sie wird im erfolgreichen wie im abgesicherten Fehlerendzustand aus sudoers entfernt. Sie ist eine Operator-Bestätigung der Clienttests, keine unabhängige kryptographische Aussage über einen fremden Mac.

Quarantäne: `/usr/local/bin/backup_notify.sh`, `/usr/local/bin/trendwatch_post.sh`, die zwei bestehenden system_doc-Crondateien, `tu1nz-bot.service` und die vier `trendwatch2-*.service`. Nur die vier zugehörigen Timer werden gestoppt. Die Service-Guards sind **keine /dev/null-Masks**, sondern verweigernde Units mit festem, nicht vorhandenem Root-Freigabemarker. Backup-Notify und Trendwatch erhalten einen festen Exit78-Guard. Dies sperrt auch andere Aufrufer genau dieser bekannten unsicheren Dateien; die akzeptierte Funktionsunterbrechung wird nicht als Ersatzimplementierung ausgegeben. Keine Compose-Down-Operation, kein künstliches Arbeitsverzeichnis und keine Containerbereinigung. Keine neuen Cronjobs.

## 18 Phasen, Beobachtung und Rollback

1. Frische private Sicherung und Driftprüfung.
2. Unabhängigen systemd-Watchdog aktivieren.
3. Feste Broker-/Lifecycle-Komponenten installieren.
4. Gemeinsame sudoers- und Unit-Prüfung.
5. Socket-Persistenz installieren und daemon-reload.
6. Docker-FDs erfassen und bewerten.
7. Inodegebundene Metadatenumstellung.
8. Root-Docker prüfen.
9. Frischen chatops-Zugriff negativ prüfen.
10. Alte Prozesskontexte negativ prüfen.
11. Monitoring und unveränderte Container prüfen.
12. Sicherheitsgrenze versiegeln, Gruppenmitgliedschaft entfernen.
13. Fünf unsichere sudo-Freigaben entfernen.
14. Bestätigte Quarantänen anwenden.
15. Broker positiv und negativ testen; kein Lifecycle-Aufruf.
16. SSH/Websites/Anwendungen und erste Mac-Bestätigung.
17. Betroffenen Autoritätsgraph und tatsächliche Rechte prüfen.
18. Prüfungen nach monoton mindestens0/30/60/91 Sekunden, zweite frische Mac-Prüfung, temporäre Bestätigungsfreigabe entfernen, Autoritätsgraph erneut prüfen, finalisieren und Watchdog kontrolliert deaktivieren.

Watchdogbudget45Minuten; Zeitmessung ausschließlich monoton plus Boot-ID. Kalenderzeit dient nur zur Ablehnung eines Zeitfensters, das mit bestehenden Root-Cron-/Trendwatch-Aufträgen kollidiert. Alle Tasks des späteren Workers laufen unabhängig von der SSH-Sitzung. Der Mac-Controller führt sequenziell neue Tailscale-SSH-Verbindungen auf22/2222, Identität chatops, HTTP200 und den festen Brokerstatus aus. Ohne passende Phasenbestätigung wird nicht abgeschlossen. Ein Verbindungsabbruch lässt den unabhängigen Watchdog zuständig. Keine iPhone-Bestätigung oder Policy-Änderung ist Teil dieser Docker-Migration.

Vor der Versiegelung stellt der Rollback ausschließlich eigene bekannte Nachbilder auf gesicherte Inhalte, Eigentümer, Modi und Zeitstempel zurück; Socket-Inode und Originalrechte werden geprüft. Atomar ersetzte reguläre Dateien können dabei neue Inodes erhalten; eine falsche Behauptung identischer Dateiinodes wird nicht gemacht. Fremde Änderungen bleiben unberührt. Vorbereitende private Evidenz und inaktive Workerdateien bleiben als Nachweis bestehen. Nach der Versiegelung bleibt Docker root-only; Rechteentzug und Quarantänen werden nötigenfalls nach vorne vervollständigt. Dieser Zustand heißt ausdrücklich `SECURED_STOP`, nicht erfolgreiche Migration oder exakter unsicherer Originalzustand. Unbeherrschbare Abweichungen bleiben `ROLLBACK_FAILED`, der Watchdog wird nicht als erfolgreich deaktiviert gemeldet.

Ein Root-Bootstrapfehler vor Start des Workers kann nur neue, inaktive Vorbereitungsdateien hinterlassen, keine Socket-/Mitgliedschafts-/sudo-Rechteänderung. Eine erneute Ausführung wird bei vorhandener Installation verweigert. Keine blinde Wiederholung. Nach einem unerwarteten Hostneustart gilt die gespeicherte Boot-ID nicht mehr; die Wiederherstellung wird angestoßen. Eine neue Socket-Inkarnation wird niemals ungeprüft auf alte Rechte zurückgesetzt.

## Offline-Nachweise und Grenzen

- 457 bisherige Tests unverändert bestanden.
- 130 neue Tests unter macOS/Python3.9 und Linux/Python3.12; Phasenfehler vor/nach allen18Schritten, Journal/Lock/Atomizität, FD-/PID-/Inode-Vertrag, unveränderte Dienstprozesse, Helperverträge, ACL-Prüfung, CLI-/Environment-Ablehnung, Watchdog nach SSH-Verlust/Bootwechsel, Sicherheitsversiegelung und Clientprüfungen.
- Der tatsächliche Host-Adapter wurde mit einem nicht ausführenden Hostmodell und realem privatem Dateijournal getestet. Diese Tests sind keine ausgeführte Produktionsmigration.
- `systemd-analyze verify` für alle vier tatsächlich erzeugten Unit-Kandidaten in isoliertem Root-Abbild: Exit0, keine Diagnose. Beide neuen sudoers-Varianten mit `visudo -cf`: Exit0. Die vollständige aktuelle sudoers-Includekette wird erst im autorisierten Root-Preflight geprüft.
- Eine Testharness-Abweichung wurde korrigiert: Eine fremde Änderung vor dem Installationssnapshot bleibt erhalten, während eigene vorangegangene Änderungen zurückgerollt werden; hierfür ist `ROLLED_BACK` korrekt. Eine isolierte Syntaxfixture war nach0440 absichtlich nicht überschreibbar; die beiden Varianten werden seitdem in getrennten Dateien geprüft. Keine produktive Rechtekorrektur.
- 701 bereits versionierte Dateien, alle42Hardening-Dateien und1125historische Nachweisdateien bytegleich. Detached Checkout weiterhin `18080ac534eae99b2d35faeba77e739fc169d6c0`, sauber. Historischer V3-Leselauf bleibt unverändert; kein neuer sudo-Sammellauf.
- Bestehende Live-Konfiguration, Container, Netzwerke, Firewall, Tailnet und SSH bleiben in dieser Vorbereitung unverändert. Keine Botnachricht, kein Provideraufruf und kein echter Docker-/Host-/Anwendungsneustart.

Aktivierungsbereitschaft bedeutet: implementierte, getestete und gebundene Transaktion mit verpflichtenden frischen Abbruchbedingungen. Es bedeutet nicht, die noch nicht autorisierten privilegierten Live-Nachweise vorwegzunehmen. Der eine spätere Terminalbefehl wird erst nach ausdrücklicher MacBook-Bereitschaft gezeigt. Er enthält genau einen interaktiven sudo-Einstieg; Passwörter werden ausschließlich verdeckt im Terminal eingegeben.

Beim abschließenden Vergleich lieferten Jellyfin und cAdvisor identische Mountdatensätze in anderer Reihenfolge. Durch vollständige Permutation der unveränderten Datensätze wurde der ursprüngliche SHA-256 exakt reproduziert. Die neue Vergleichslogik sortiert nur nach eindeutiger Destination; sie behält sämtliche Felder bei und lehnt doppelte Ziele ab. Regressionstests erlauben Reihenfolgeänderung, erkennen aber beispielsweise geändertes RW. Der ursprüngliche private Snapshot bleibt unverändert; ein zusätzlicher kanonischer Snapshot ist durch den Permutationsnachweis daran gebunden.
