# Root-Zugangswege: vorbereitende Bestandsaufnahme

Status: PRIVILEGED_INVENTORY_REQUIRED. Keine Live-Migration freigegeben oder ausgeführt.
Dieser Auftrag erlaubt jetzt die Vorbereitung der Bereinigung; der ursprüngliche
Blockerbericht bleibt als historischer Befund unverändert erhalten.

## Bestätigte Funktionsabhängigkeiten

| Bestehende Freigabe | Befund | Geplanter Ersatz / noch offene Prüfung |
|---|---|---|
| pandoc | Aktive Docs-Wrapper führen root-eigenes tu1nz_doc_pipeline.py als chatops aus; integrierte Pipeline erzeugt PDF ohne Pandoc | NOPASSWD entfernen, frischer PDF-No-Push-Test vor Migration erforderlich |
| mkdir/chown | Allgemeine Freigaben ohne Argumentbindung; /opt/docs gehört bereits chatops, 0755 | Konkrete nötige Zielverzeichnisse vorab inventarisieren; keine pauschale Eigentümeränderung |
| tee upload_log | Datei chatops:chatops 0664, Elternverzeichnis chatops:chatops 0755, Basis-ACL; Pfad durch Benutzer ersetzbar | Root-tee entfernen; unprivilegiertes Logging bevorzugen, Aufruferprüfung noch nicht vollständig |
| altes Golden-Skript | /opt/tu1nz_repos/infra/t1nz_create_golden.sh chatops:chatops 0755, Eltern 2770 | NOPASSWD entfernen; nicht als sicheren Root-Ersatz kopieren |
| Docker | Socket root:docker 0660, GID987 | Mitgliedschaft entfernen plus kontrollierte Erneuerung aller betroffenen Prozesse; nur feste Brokerdiagnosen |

Das alte Golden-Skript kopiert /etc, /opt/tu1nz_repos, /opt/n8n und
/var/spool/cron mit sudo rsync, legt /opt/tu1nz_golden an und erzeugt Prüfsummen.
Es wurde nicht ausgeführt, auch nicht im Dry-run.
Die AKTIVE Golden-Unit benutzt dagegen /usr/local/bin/t1nz_create_golden.sh,
root:root 0755, User/Group chatops. Sie ist inaktiv, ihr Timer aktiv/wartend.
Drop-ins setzen NoNewPrivileges, leere Capability-Sets und restriktive Sandbox.
Die aktive Fassung benötigt kein sudo, schreibt /opt/tu1nz_snapshots sowie Logs,
kann optional Pandoc unprivilegiert verwenden und enthält Git-Push-/Telegrampfade.
Deshalb wurde sie nicht testweise gestartet. Das ist kein Beleg, dass alle
historischen oder manuellen Aufrufer des alten Skripts entfallen sind.

Upload-Log-Leser: monthly_sysstatus.sh; trim_upload_log.sh benutzt einen festen
/tmp/upload_log_trim.txt und anschließendes mv. Ausführungsidentität und Aufrufer
müssen vor der Entscheidung über einen Ersatz vollständig geklärt sein.
trendwatch_post.sh enthält ebenfalls sudo mkdir; keine Entfernung vor Aufruferprüfung.

## Prozessgruppen sind eine eigene Migrationsabhängigkeit

Neben SSH, Bash, tmux, ssh-agent und dem Benutzer-systemd tragen folgende
laufende Dienste derzeit Docker-GID987:

- tu1nz-adult-public-s8-telegram.service
- tu1nz-adult-public-s10-wms.service
- tu1nz-adult-public-s8-landing.service
- tu1nz-adult-public-s7.service

Alle laufen als chatops:chatops; SupplementaryGroups ist in der effektiven
systemd-Auskunft leer, die tatsächlichen Prozesse besitzen jedoch die ergänzenden
Login-Gruppen. Nur gpasswd/usermod zu ändern reicht deshalb nicht.
Jellyfin hat ebenfalls UID1001, aber NICHT Docker-GID987. Ein killall für UID1001
wäre falsch und ist ausgeschlossen. PIDs sind kurzlebig und müssen unmittelbar
vor jeder späteren Migration samt Startzeit und cgroup erneut geprüft werden.
Dienstneustarts benötigen eine genaue Inflight-/Health-/Rollback-Bewertung.
Rollback kann Gruppen und Konfiguration wiederherstellen und Dienste neu starten,
aber beendete interaktive Shells und deren flüchtigen Zustand nicht bytegleich
rekonstruieren. Diese Grenze darf nicht als exakter Prozessrollback verschleiert werden.

## Weitere Schnittstellen und verbleibende Lücken

Unprivilegierte Metadatenprüfung in /usr/bin, /usr/sbin, /usr/local/bin und
/usr/local/sbin fand die üblichen Setuid-/Setgid-Programme einschließlich sudo,
su, mount, passwd, newgrp, at, crontab und Mail-Hilfsprogramme. Keines der dort
gefundenen privilegierten Programme war für chatops direkt schreibbar.
ping und mtr-packet tragen Dateicapabilities. Das ist weder ein Exploitnachweis
noch eine vollständige Prüfung aller Dateisysteme/Capabilities/Polkit-Regeln.
Docker ist schreibbar; containerd-Socket nicht. Der beschreibbare D-Bus-Socket
beweist für sich allein keine Polkit-Autorisierung.

/etc/sudoers, sudoers.d und Polkit-Regelverzeichnisse sind nicht vollständig
unprivilegiert lesbar. Exakte Quelldateien, Includes, Aliase, allgemeine Regeln
und deren historische Herkunft bleiben daher offen. Keine bestehende Root-Lücke
wurde zum Lesen dieser Daten benutzt.

## Genau ein vorbereiteter lesender sudo-Schritt

scripts/tu1nz_privilege_inventory.py ist ein einmaliger Sammler, KEIN Broker,
KEINE sudoers-Freigabe und KEIN Installer. Er verlangt Root und keine Argumente.
Er erfasst feste Pfade samt Eltern, numerischen ACLs, Eigentümern, Modi und Hashes
sowie numerische Identitäten der chatops-Prozesse. Er schreibt keine Konfiguration.
getfacl ist der einzige Kindprozess; feste Umgebung, keine Shell, Timeout,
Prozessgruppenbereinigung und begrenzte eingelesene Ausgabe. Anonyme temporäre
Ausgabedateien werden geschlossen; JSON wird in einem neuen privaten Nachweis
abgelegt. Keine Rohdateien, Prozessargumente, Umgebungswerte oder Journaltexte.
Nur die bereits bekannten exakten sudo-Grants werden im Klartext ausgegeben;
unbekannte Definitionen bleiben mit Zeilennummer/Hash UNREVIEWED. Der Lauf endet
bewusst INCOMPLETE/Exit2, bis die gesondert bezeichneten Prüfbereiche geklärt sind.
Das ist kein vollständiger sudo-/Polkit-Parser und kein Nachweis sicherer Policy.

Der lokale Launcher lädt die geprüften Skriptbytes einmal, vergleicht SHA-256 und
übergibt genau diese Bytes an Python mit -I nach einer einzigen sudo-Abfrage.
Keine Ausführung fand statt. Persönliche Eingabe erst nach erneuter expliziter
Bereitschaft. Auch danach wird nur gelesen, keine Migration gestartet.

Zehn Offline-Tests bestanden lokal und unter Server-Python: bekannte Grants,
Unterdrückung unbekannter Inhalte, Include-Markierung, Kommentare, Zusatzargumente,
Root-Gate, Symlinkbehandlung, ACL-/Dateiinhaltsunterdrückung, fehlendes Programm
und Timeout mit Prozessgruppenbeendigung. Keine produktiven privilegierten Tests.

## Noch nicht fertig / Aktivierungssperre

Broker, Funktionsersatz, exakte sudoers-Patches, atomare Migration, Root-Watchdog,
vollständiger Offline-Rollback und dessen Fehler-Injektionen sind noch NICHT
fertiggestellt. Deren sichere Eingaben hängen von der geschützten Inventur und
dem Dienstplan ab. Keine positiven Ergebnisse oder PDF-Neutests werden behauptet.

Späterer Entwurf: root-geschützte Sicherung aller konkret betroffenen Dateien,
ACLs und Gruppen; unabhängiger Root-Watchdog vor Mutationen; Ersatz installieren;
visudo-Gesamtprüfung; exakt belegte Grants entfernen; Docker-Mitgliedschaft und
nur bestätigte Prozesse erneuern; neue SSH-Sitzung, sudo -k, vollständige
Positiv-/Negativtests; erst danach fest begrenzte Finalisierung. Fehlende oder
nicht exakt wiederherstellbare Vorbedingungen blockieren die Aktivierung.

Keine Live-Rechte/Gruppen/Dienste/Container verändert, kein PR. Der detached
Produktionscheckout bleibt bei 7c634d3b82572e8459d51c69f04dce82c624d766.
