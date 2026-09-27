# Privilegierte Inventur v1: Ergebnis und Grenzen

Der persönlich freigegebene lesende Lauf wurde ausgeführt. Bericht:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/root-access-inventory-jsxfuso1/inventory.json`
SHA-256: `c46b7426252c410b8aa329564fa44208a712646383b9d8ceb6f4e0db531b2176`.
Version 1.0.0, 44 Pfadabschnitte, keine globale Exception. Status INCOMPLETE,
wie vom Sammler vorgesehen; kein erfolgreicher Gesamtabschluss der Inventur.
Der Bericht bleibt unverändert und wird nicht ins Repository aufgenommen.

## Nachgewiesene Herkunft der fünf Grants

| Quelle | Zeile | Definition |
|---|---:|---|
| /etc/sudoers | 58 | chatops ALL=(ALL) NOPASSWD: /usr/bin/tee -a /opt/docs/upload_log.txt |
| /etc/sudoers | 60 | chatops ALL=(root) NOPASSWD: /opt/tu1nz_repos/infra/t1nz_create_golden.sh |
| /etc/sudoers.d/99-dokuagent-pandoc | 1 | chatops ALL=(ALL) NOPASSWD: /usr/bin/pandoc |
| /etc/sudoers.d/chatops-nopass | 1 | chatops ALL=(ALL) NOPASSWD: /bin/mkdir, /bin/chown |

Diese Dateien sind root:root 0440 mit Basis-ACL ohne benannte Einträge.
Exakte Quelldatei-Hashes stehen im privaten Bericht. Die übrigen Definitionen in
/etc/sudoers, 90-cloud-init-users und trendwatch-restart wurden NICHT inhaltlich
freigegeben: v1 speichert für unbekannte Zeilen nur Nummer und Prüfsumme.
Die Benennung einer Datei beweist nicht ihre effektive Autorisierung. Includes,
Aliase und Reihenfolge müssen vor jeder Entfernung vollständig aufgelöst sein.
Historische Herkunft ist noch nicht vollständig rekonstruiert.

## ACL-Aufrufabweichung, offline korrigiert

41 von 43 getfacl-Statusobjekten melden complete=false, trotz Returncode0 und
vorhandener ACL-Daten. Ursache ist für den festen Aufruf auf /etc reproduziert:
getfacl ohne -p schreibt den 55-Byte-Hinweis über entfernte führende Schrägstriche
auf stderr. Derselbe lesende Aufruf mit -p liefert identische ACL-Daten ohne
stderr. Der alte Bericht wird deshalb nicht nachträglich umklassifiziert.

Sammler 1.0.1 ergänzt -p; stderr bleibt grundsätzlich ein Fehler. Zusätzlich
werden nun alle besuchten Verzeichnisse und übersprungenen Verzeichnis-Symlinks
als Metadaten erfasst; v1 erfasste leere Unterverzeichnisse nicht vollständig.
Es fand KEIN erneuter privilegierter Lauf statt. 12 Offline-Tests bestanden,
einschließlich exakter getfacl-Argumente und weiterhin abgewiesener stderr-Ausgabe.
Voränderungssicherung:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/inventory-review-20260927T111800Z`.
Historischer Launcher ist durch den alten Skript-Hash nun absichtlich gesperrt.

## Polkit: zusätzliche zu bewertende Befugnis

Die unprivilegiert lesbaren /usr/share/polkit-1/rules.d-Dateien stimmen per SHA
mit der privilegierten Inventur überein. 49-ubuntu-admin.rules und 50-default.rules
benennen sudo (und teilweise admin) als Administratoridentitäten. Das allein ist
keine allgemeine passwortlose Berechtigung.

org.freedesktop.packagekit.rules gibt jedoch upgrade-system und
trigger-offline-update mit polkit.Result.YES frei, wenn die Sitzung lokal und
aktiv ist und das Subjekt zur Gruppe sudo gehört. chatops bleibt nach Zielbild
in sudo. Die Freigabe ist bedingt; ein entfernter SSH-Aufruf ist dadurch nicht
automatisch erlaubt. Dennoch widerspricht sie möglicherweise dem globalen Ziel
„ausschließlich Broker ohne Passwort“, falls chatops eine aktive lokale Sitzung
hat. Keine Aktion wurde ausgelöst. Kein pauschaler Entzug von sudo und keine
Polkit-Änderung. Lokale Overrides, Policy-Defaults und effektive Priorität sind
noch nicht vollständig geprüft.
GeoClue-/networkd-Regeln benennen andere Dienstbenutzer; daraus wurde keine
chatops-Freigabe abgeleitet.

## Prozessbefund und Aktivierungssperre

19 UID1001-Prozessdatensätze, davon 15 mit ergänzender Docker-GID987, einschließlich
kurzlebiger Diagnose-/SSH-Prozesse. Die zuvor identifizierten vier öffentlichen
Dienste bleiben vom Prozess-Erneuerungsplan betroffen. Keine Prozesse beendet.

Keine Live-Migration, kein neuer sudoers-Eintrag, keine Brokerinstallation.
Die vollständige Migration kann noch nicht als vorbereitet gelten: unbekannte
sudo-/Polkit-Definitionen, vollständige privilegierte Schnittstellenabdeckung,
Funktionsersatztests und ein belastbarer Dienst-/Rollbackplan fehlen.
Insbesondere darf die PackageKit-Bedingung nicht stillschweigend ignoriert werden.
Die bestehende Inventur ist ein Teilnachweis, kein Sicherheitsfreibrief.

Nur Repository-Korrektur und Ergebnisdokumentation werden committed/gepusht.
Kein PR. Private Rohdaten bleiben außerhalb Git; der detached Checkout bleibt
unverändert. Nächster privilegierter Prüfschritt benötigt einen neu geprüften,
vollständig auf die offenen Bereiche ausgerichteten Sammler, keine Wiederholung
des unzureichenden v1-Aufrufs.
