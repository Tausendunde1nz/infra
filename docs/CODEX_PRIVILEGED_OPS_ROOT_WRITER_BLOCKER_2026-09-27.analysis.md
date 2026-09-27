# Privilegienmigration: bestätigter unabhängiger Root-Schreibpfad

Stand: 2026-09-27. Arbeitsbasis b88e2a8d0e96e42342a240bd404454a49993326b.
Status: **SECURITY BLOCKER / KEINE AKTIVIERUNGSFREIGABE**.

Der Auftrag erlaubt einen Stopp bei einem konkreten Sicherheitsblocker, der
nicht ohne Live-Eingriff auflösbar ist. Dieser Fall ist eingetreten. Es wird
keine vollständige Broker-/Installer-/Watchdog-Implementierung behauptet und
kein Aktivierungsbefehl ausgegeben. Die bestehenden Modelle bleiben Modelle.

## Nachgewiesene Vertrauensgrenzenverletzung

Alle vier Units
`trendwatch2-morning.service`, `trendwatch2-midday.service`,
`trendwatch2-afternoon.service`, `trendwatch2-evening.service`
starten exakt `/usr/local/bin/trendwatch_post.sh`.
Die effektiven systemd-Eigenschaften zeigen leeres User/Group bei Systemunits,
also standardmäßig root; ProtectSystem=no, ProtectHome=no,
NoNewPrivileges=no. RootDirectory, RootImage, ReadOnlyPaths, ReadWritePaths,
InaccessiblePaths und DropInPaths sind leer. Alle vier zugehörigen Timer
sind aktiv/waiting. Die letzten abgeschlossenen Läufe zeigen Result=success
und ExecMainStatus=0. Es wurde kein Lauf ausgelöst.

Das Skript ist root:root 0755, ohne zusätzliche Access-ACL. Seine unverändert
mit V3 übereinstimmenden Bytes enthalten an Zeile23 `sudo mkdir -p /opt/trendwatch`
und an Zeile24 eine Pipeline des Trendtitels nach
`sudo tee /opt/trendwatch/today_title.txt` (Ausgabe unterdrückt, Fehler toleriert).
Der Pfad wird nicht mit O_NOFOLLOW geöffnet und nicht gegen einen unveränderbaren
Verzeichnisdeskriptor gebunden. Ein root-eigenes Skript allein schützt seine
Schreibziele nicht.

| Objekt | Eigentümer | Modus | ACL / Bedeutung |
|---|---|---|---|
| /opt | root:root | 0755 | nur Basis-ACL; chatops nicht schreibberechtigt |
| /opt/trendwatch | chatops:chatops | 0755 | nur Basis-ACL; chatops kann Einträge ersetzen |
| /opt/trendwatch/today_title.txt | chatops:chatops | 0644 | reguläre Datei, aktuell kein Symlink |
| /usr/local/bin/trendwatch_post.sh | root:root | 0755 | root-eigenes Programm schreibt durch fremd kontrolliertes Verzeichnis |

Der unter UID1001 durchgeführte effektive Schreibbarkeitstest bestätigt die
Verzeichnisberechtigung. Keine Default-ACL und kein Sticky-Bit verhindern den
Austausch des Eintrags. Ein kontrollierter Eintrag kann den nachfolgenden
Root-Schreibvorgang auf eine andere Datei umlenken. **Bestätigt ist ein
Root-Schreib-/Integritätsrisiko; weder tatsächliche Ausnutzung noch eine
bestehende Kompromittierung werden behauptet.** Es wurde keine produktive
Datei ersetzt und kein privilegierter Exploit ausgeführt.

Dieser Root-Timer-Pfad besteht unabhängig von chatops' sudo-Freigaben und
Docker-Mitgliedschaft. Ihre Entfernung hebt die Root-Identität der Timer
nicht auf. Die separat ausgenommene sudo-Regel `trendwatch-restart` für daniel
ist ein anderes Objekt und bleibt unverändert. Die hier betroffenen vier
vorhandenen Root-Timer sind nicht die vier öffentlichen Dienste der geplanten
Gruppenmigration.

## Warum reine Offline-Vorbereitung den Blocker nicht beseitigt

Neue Brokerdateien und neue sudoers-Regeln ändern die bereits aktiven
Root-Schreibwege nicht. Der geforderte sichere Endzustand wäre damit nicht
belegt. Erforderlich ist eine eigene, eng begrenzte Absicherung des tatsächlich
laufenden Trendwatch-Schreibwegs: entweder ein nachgewiesen vollständig
unprivilegierter Ablauf oder ein fest gebundener, symlink-/race-sicherer
Schreibweg mit getesteten Funktionsersatz- und Rollbackbedingungen.
Das betrifft bestehende Live-Skripte beziehungsweise Dienstidentitäten und
benötigt deren Abhängigkeitsprüfung und eine eigene Live-Freigabe.

Kein pauschales chown/chmod des gemeinsam verwendeten Verzeichnisses, kein
Abschalten der Timer und keine Umstellung ihrer Identitäten wurde vorgenommen.
Es wird auch keine dieser Änderungen als automatisch funktionsgleich behandelt.
Vor Fortsetzung müssen dieser Pfad und die Ersatzfunktionen nachweislich sicher
sein. Ein isolierter Reproduktionstest repariert das Produktionssystem nicht.

## Nachweise und unveränderte Originale

Privater, bereinigter Metadatenbeleg (Verzeichnis0700, Datei0600):
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/privilege-root-writer-review-20260927T122551Z/evidence.json`

SHA-256: `4126339d11212f669d193b62dd1ad160b17cbc42fe0a369eb785b51848c689f4`.

Er enthält keine Skript-Rohinhalte, Tokens, Nachrichten oder Umgebungswerte.
Die vier Unitdateien und das Schreibskript stimmen bytegenau mit den
V3-Nachweisen überein. Der Befund ist damit vorbestehend.
Skript-SHA: `467b326823d46de284bf037363c18d350b0c3a5446e759b96683184ea1922264`.
Alle1.125 in file_hashes referenzierten V3-Dateien wurden erneut geprüft:
keine Abweichung. Manifest und historische Klassifikation bleiben unverändert.
Private Nachweise werden nicht committed.

## Zusätzliche Aktualisierung der späteren Vorbedingungen

Die V3-Sicherungen bleiben Beweisgrundlage; ein Installer darf sie nicht blind
als aktuellen Live-Rollbackstand einsetzen:

- Die aktuelle S8-Telegram-Unit hat SHA
  `a01def648eb2252ec79bcf465370d927ef6085e3ba97284a1042f8a4c61e9420`
  statt V3 `fcad30a40a51ac9d45472cbe3e5eb607ccf117f820fe7f9a5d581f455aa63665`.
  Unter anderem fehlen jetzt die früheren experience-contract/-copy-Argumente.
- Der aktuelle S10.1-Health-Prüfer hat SHA
  `15cc2cfa6c38e4ee6c5cc3689b62011672b9304a4d0709e3062c87e3d49ba019`
  statt V3 `36a9d1f1e12779fc1459336a83a8c14c5ba2d21f21357096ffb0d72e6fd97298`.
- Der canonical Control-Checkout steht wieder clean/detached auf
  `7c634d3b82572e8459d51c69f04dce82c624d766`. Reflog belegt den zwischenzeitlichen
  Wechsel von e266830 zurück; diese Sitzung führte keinen solchen Wechsel aus.
- Zusätzlich zu den vier öffentlichen Diensten trägt der laufende
  `tu1nz_agentmode.service` (chatops) die ergänzende Docker-GID987.
  Er startet `/usr/local/bin/tu1nz_sync_all.sh --loop`. Ein bloßes Beenden
  der SSH-Sitzungen und Neustarten der vier öffentlichen Dienste würde die
  geforderte vollständige Gruppenrevokation deshalb nicht erfüllen.
  Sein Wiederanlauf kann Docs-Synchronisation und Übergangsbenachrichtigungen
  ausführen; er darf nicht als beliebiger Sitzungsprozess beendet werden.
- Sein vorhandener Zustandsbeleg meldet CONTROL_LOCAL_STATE_INVALID bei
  DOCS_SYNCED; der Code verlangt für die Control-Prüfung einen benannten Branch,
  während der vorhandene Checkout detached bleiben soll. Keine Reparatur dieses
  vorbestehenden Widerspruchs gehört zu diesem Lauf.

Diese zusätzlichen Befunde wurden nur lesend erhoben. Keine fremde Änderung
zurückgesetzt, kein neuer Sollzustand daraus stillschweigend abgeleitet.
PackageKit und die daniel-Regel bleiben wie im Auftrag festgelegt unverändert.

## Offline-Validierung und Grenzen

Neu: neun Tests für die eng gefasste Befundklassifikation und die Dateisemantik.
Sie behandeln implizites/ausdrückliches root, fehlende Nachweise, unbekannte
Sandboxkonfiguration, abweichende Dienstidentität, unveränderten Root-Schreibpfad
nach Entzug anderer Rechte sowie zwei ausschließlich unprivilegierte
Dateisystem-Fixtures. `/usr/bin/tee` folgt dort einem ausgetauschten Symlink;
O_NOFOLLOW verweigert denselben Vorgang und erhält die separate Fixturedatei.
Alle Dateien befinden sich in einem automatisch bereinigten privaten Testbaum.
Die Tests verweigern Ausführung als root. Kein produktives Ziel, kein sudo,
kein Timer und keine Nachricht werden ausgeführt.

Zusammen mit den bisherigen69 gezielten Tests: **78 Tests bestanden**.
Der neue reine Klassifikator ordnet den aktuellen privaten Beleg als
BLOCKED_ROOT_WRITE_THROUGH_CHATOPS_DIRECTORY ein. NOT_THIS_FINDING bedeutet
niemals allgemeine Sicherheitsfreigabe. Unbekannte Sandboxzustände bleiben
REVIEW_REQUIRED. Dies ist kein vollständiger Broker-/Migrations-/Live-
Rollbacktest und ersetzt ihn nicht.

Reproduktion aus scripts/:

```text
/usr/bin/python3 -B -m unittest -q test_privilege_root_writer_guard.py test_pkcheck_review.py test_privilege_followup_v3.py test_privilege_sudo_candidate.py test_privilege_inventory_v2.py test_privilege_inventory.py
```

## Änderungsumfang und Rollback dieses Vorbereitungslaufs

Ausschließlich neue Klassifikations-/Testdateien und diese Analyse im separaten
Worktree; zusätzlich ein privater Metadatenbeleg. Keine bestehenden Dateien
überschrieben. Daher keine Live-Sicherung rückzuspielen und keine Dienste
zurückzurollen. Ein späterer Repository-Revert kann nur diesen neuen Commit
rückgängig machen; historische Belege bleiben erhalten.
Kein Installer, Watchdog, Countdown oder Broker wurde auf dem Host aktiviert.
Keine Änderung an Gruppen, sudoers, Polkit, Firewall, SSH, Containern oder
canonical Checkout. Kein PR. Der Branch wird mit dem bestätigten Blocker
weitergeführt, nicht als aktivierungsbereit deklariert.
