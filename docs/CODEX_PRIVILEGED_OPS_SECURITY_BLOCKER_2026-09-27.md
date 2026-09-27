# Privileged Operations Broker v1: Sicherheitsblocker

Status: NO-GO für Implementierung eines aktivierbaren Installers und Live-Installation.
Die Bestandsaufnahme erfolgte ausschließlich lesend, ohne privilegierten Aufruf,
ohne Ausführung eines Exploits und ohne Änderung bestehender sudo-Regeln.

## Basis und unveränderter Zustand

Integrationsbasis: `0f46b65649c6d5c5eefcee04f7689bafd4a4db94` (`origin/control-main`).
Arbeitsbranch: `security/codex-privileged-ops-2026-09-27`.
Separater Worktree: `/opt/tu1nz_repos/worktrees/codex-privileged-ops-2026-09-27`.
Produktionscheckout `/opt/tu1nz_repos/control`: detached bei
`7c634d3b82572e8459d51c69f04dce82c624d766`, sauber.
Es wurden weder Broker noch sudoers-Datei, Watchdog oder Launcher installiert.
Keine Container-, Netzwerk-, SSH-, Firewall-, Dienst- oder Gruppenänderung.

## Bestätigte Rechte

`chatops`: UID/GID 1001; zusätzliche Gruppen adm(4), sudo(27), users(100),
docker(987), systemd-journal(999).
Docker-Gruppe: chatops. Sudo-Gruppe: daniel, chatops.
Adm: syslog, netdata, chatops. Systemd-journal: chatops.
Diese Gruppenauskunft beschreibt die von getent gemeldeten expliziten Mitglieder.

`/var/run/docker.sock`: root:docker, 0660, für chatops lesbar und schreibbar.
Der Zugriff auf die privilegierte Docker-API ist technisch root-äquivalent.
Ein Broker kann diese bestehende Fähigkeit nicht einschränken.
`/run/containerd/containerd.sock`: root:root, 0660, nicht schreibbar für chatops.
`/run/dbus/system_bus_socket`: root:root, 0666; Socketzugang allein ist kein
Nachweis privilegierter Polkit-Autorisierung.
`/etc/sudoers` (0440), `/etc/sudoers.d` (0750) und
`/etc/polkit-1/rules.d` (0750) sind für chatops nicht lesbar.
Deren vollständiger Inhalt wurde ausdrücklich nicht über Docker beschafft.

`sudo -n -l` war ohne Passwort erfolgreich und meldete:

- `(ALL : ALL) ALL` (allgemeines, grundsätzlich passwortpflichtiges sudo),
- `(ALL) NOPASSWD: /usr/bin/pandoc`,
- `(ALL) NOPASSWD: /bin/mkdir, /bin/chown`,
- `(ALL) NOPASSWD: /usr/bin/tee -a /opt/docs/upload_log.txt`,
- `(root) NOPASSWD: /opt/tu1nz_repos/infra/t1nz_create_golden.sh`.

Die mkdir-/chown-Einträge enthalten keine Argumentbegrenzung. Besonders kritisch:
`t1nz_create_golden.sh` gehört chatops:chatops, Modus 0755, und ist für chatops
beschreibbar. Es wurde weder geändert noch ausgeführt. Bereits die Kombination
von Schreibrecht und passwortloser Root-Ausführung ist ein allgemeiner
Root-Eskalationsweg. Eine inhaltliche Untersuchung des Skripts ist dafür nicht nötig.

## Auswirkung auf den Auftrag

`/usr/local/sbin` ist root:root 0755 und derzeit für chatops nicht direkt schreibbar;
`/usr/local/sbin/tu1nz-codex-ops` existiert nicht. Mit dem bereits unbeschränkt
freigegebenen chown lässt sich diese Eigentümerschutzgrenze jedoch umgehen.
Ein neu installierter Broker wäre deshalb nicht belastbar gegen Manipulation
durch chatops geschützt. Dies ist ein vorbestehender Befund, keine durch den
geplanten Broker neu geschaffene Eskalation.

Negative Tests nur für `sudo -n id`, Shell oder Python würden diesen Zustand
nicht widerlegen: Direktaufrufe können abgewiesen werden, während die oben
bestätigten indirekten Root-Wege weiter bestehen. Ein solcher Testabschluss darf
nicht als Nachweis fehlender allgemeiner Root-Rechte ausgegeben werden.

Der ausdrücklich erwartete Docker-Befund allein wäre kein neuer Anlass für einen
Abbruch gewesen. Die zusätzlich festgestellten unbeschränkten sudo-Fähigkeiten
und das beschreibbare Root-Skript verhindern aber die zugesagte Integritätsgrenze.
Bestehende sudo-Regeln sollen laut Auftrag unverändert bleiben. Eine Bereinigung
wäre daher ein gesondert zu bewertender und freizugebender Auftrag.

## Geplanter, noch nicht implementierter Funktionsumfang

Wiederholt benötigte Diagnosen aus den bisherigen Hardening-Arbeiten:
aktive Kernel-Firewallregeln/NAT, effektive OpenSSH-Konfiguration, Fail2ban-Status,
Dienstidentitäten, ACL-Metadaten sowie begrenzte Proxy-/Journalnachweise.
Historische Referenzen sind die integrierten Network-Hardening- und
Spicymila-Untersuchungsdokumente sowie der Sammler v2/v2.1. Der Sammler darf
nicht einfach als benutzerveränderbares Repository-Skript für Root freigegeben werden.

Eine spätere v1 benötigt eine exakte Operations- und Ausgabefeld-Allowlist,
root-geschützte Interpreter-/Importkette, feste Umgebung, keine Benutzerpfade,
keine Shell, feste Argumente, Laufzeit- und Ausgabelimits, Prozessgruppenbereinigung,
Sperre sowie bereinigtes Journal-Audit. Root-Ausgaben dürfen weder private
Dateiinhalte noch Umgebungswerte, Tokens oder unbereinigte Journaltexte enthalten.
Jede sudoers-Zeile muss genau eine freigegebene Operation mit NOSETENV benennen.
`finalize-install` darf ausschließlich die eigene root-gesicherte Transaktion
nach nachgewiesenen Abschlussprüfungen finalisieren.

## Freigabe- und Testgrenze

Noch NICHT vorhanden oder bestanden: Brokerimplementierung, synthetische
Operationstests, Manipulations-/Timeouttests, visudo-Gesamtprüfung,
Installationstransaktion, automatische Rollbackprüfung und unabhängige SSH-Abnahme.
Kein vorbereiteter ausführbarer Installationsbefehl wird behauptet.
Vor einer Umsetzung müssen die bestehenden Root-Wege bewertet und die gewünschte
Schutzgrenze ausdrücklich geklärt werden. Gruppen werden nicht eigenmächtig geändert.
Eine neue Bereitschaftsbestätigung allein behebt den technischen Befund nicht.

Die einzige Änderung dieses Branches ist diese Diagnose. Bestehende Dateien und
historische Nachweise bleiben bytegleich; daher sind keine Live-Backups oder
Rollbackaktionen erforderlich. Rücknahme der Vorbereitung: Dokumentationscommit
bei Bedarf regulär revertieren, niemals Produktionskonfiguration zurücksetzen.
Kein PR wird erstellt.
