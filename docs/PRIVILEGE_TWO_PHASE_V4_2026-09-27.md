# Zweiphasige Privilegienmigration V4 – Komponenten und notwendige Leselücke

Basis: f8979c0b18574a7919a02c3ed7e990c457b9b875.
**Status: PREPARATION / PRIVILEGED_READ_REQUIRED. Nicht aktivierungsbereit.**
Keine Live-Datei, Unit, Timer, Gruppe, sudoers-Regel, ACL, Polkit-Regel,
Firewall, Container oder canonical Checkout wurde verändert. Kein Watchdog,
Countdown, PR oder Telegram-Versand. Historische Implementierungen und Nachweise
bleiben erhalten. Die zwei Phasen dürfen noch nicht aktiviert werden.

## Bestätigte Trendwatch-Kette

| Baustein | Ausführung / Funktion | Pfade / Abhängigkeiten |
|---|---|---|
| vier trendwatch2-Poster | System-Units ohne User, damit root; oneshot | jeweils exakt /usr/local/bin/trendwatch_post.sh |
| trendwatch_post.sh | eval der Fetch-Ausgabe, Titeldatei schreiben, Affiliate-Text, Telegram sendMessage | /opt/trendwatch/today_title.txt; liest today_live_title.txt zweimal; inline Telegram-Credentials |
| trendwatch_fetch.sh | feste Titel-/Score-/Trendliste; zusätzlicher YouTube-HTTP-Aufruf | liest yt_api_key.txt; das abgefragte YouTube-Ergebnis wird nicht als Shell-Zuweisung ausgegeben und nicht in der Nachricht verwendet |
| tw_affiliate.sh | Score0.62 wählt remix, mittlere Preisgruppe | root-eigene JSON-Konfigurationen unter /etc; zwei mögliche Produkt-Schlüssel; keine eigenen Dateien/Netzaufrufe |
| tw_youtube_live.sh | YouTube-LIVE-Fetch mit Filter/Fallback | schreibt youtube_live_raw.json, today_live_title.txt, optional today_live_thumbnail.txt unter /opt/trendwatch |
| trendwatch-fetch.service | chatops; disabled/inactive, kein bisheriger ExecMain-Zeitstempel | tw_fetch.js und ExecStartPost-Pipeline mit trendwatch_post.sh send; EnvironmentFile /etc/tu1nz/trendwatch.env |
| trendwatch2-fetch.service | chatops; disabled/inactive | tw_fetch.js; eigener Baum /opt/trendwatch2, kein Beleg für Identität mit /opt/trendwatch |
| trendwatch_tu1nz.service | root-Konfiguration, disabled/inactive | historischer separater /opt/trendwatch_bot-Pfad; nicht stillschweigend aktivieren |

Das aktuelle post-Skript ignoriert den übergebenen Parameter send und den
komponierten stdin-Text. Daher ist die deaktivierte Fetch-Pipeline kein Beleg
für einen zweiten benötigten Nachrichteninhalt, aber ein vorhandener Aufrufweg,
der bei einer Installation nicht unbemerkt gebrochen werden darf.

Die Skriptsuche unter /usr/local/bin und die lesbaren systemd-/Cron-Verzeichnisse
fand keinen Aufrufer für tw_youtube_live.sh. Das beweist **keine** Entbehrlichkeit:
Root-/Benutzer-Crontabs sind geschützt. Die untersuchten aktuellen Git-Bäume von
Control, Infra, Adult-Core und den beiden Bot-Anwendungen lieferten keinen
weiteren today_title-/today_live_title-Verbraucher. Historische/geschützte oder
externe Verbraucher sind dadurch nicht ausgeschlossen.

/opt/trendwatch ist chatops:chatops0755. today_title.txt ist0644 und chatops-eigen;
today_live_title.txt und youtube_live_raw.json sind chatops-eigen0664.
today_live_thumbnail.txt ist root:root0644, aber sein Verzeichniseintrag bleibt
von chatops austauschbar. debug/ enthält weitere chatops-eigene Daten.
yt_api_key.txt liegt dort lesbar als0644; sein Wert wurde weder ausgegeben noch
committed. Aus der Eigentümerschaft allein wird kein funktionaler Schreibbedarf
abgeleitet. Eine vollständige Einstufung verlangt die geschützten Cron-Daten.

## Timer und Nachrichtenverhalten

Serverzeitzone: Etc/UTC. OnCalendar ist jeweils täglich08:00,12:00,15:00,19:00
in dieser Zeitzone, nicht implizit Europe/Berlin. Am27.09. sind dies10:00,14:00,
17:00,21:00 Berliner Zeit. Alle vier Timer: Persistent=yes, AccuracyUSec=1min,
RandomizedDelayUSec=0, active/waiting. Beim belegten Prüfzeitpunkt waren die
nächsten Ausführungen15:00/19:00 UTC desselben Tages sowie08:00/12:00 UTC des
Folgetages. Dies ist eine Beobachtung, keine spätere Aktivierungsfreigabe.

Die Timerdateien sollen unverändert bleiben; kein stop/start/enable der Timer
für den Austausch der Serviceimplementierung. Ein Neustart von Persistent-
Timern könnte eine verpasste Ausführung nachholen. Ein gemeinsames Serviceziel
wird vorerst NICHT gewählt: systemd kann zusammenfallende Startanforderungen
zusammenfassen, und ohne vier eindeutige Kontextkennungen wäre keine belastbare
Slot-Zuordnung möglich. Vier Servicekontexte können dieselbe Implementierung
und eine gemeinsame exklusive Zustandssperre nutzen.

Vor einer späteren Transaktion muss das vollständige Deadline-/Rollbackfenster
vor dem nächsten möglichen Timerlauf liegen, mit Sicherheitsabstand zur
Genauigkeit des Timers. Kein Timerlauf darf während eines nur teilweise
installierten Zustands auftreten. Sonst vor der ersten Änderung abbrechen.
Es wurde weder ein Countdown gestartet noch auf einen echten Post gewartet.

## Implementierte, noch nicht deploybare Komponenten

`scripts/tu1nz_trendwatch_v4.py`:

- unprivilegierter Zustands-/Formatierungs-/Versandablauf; root-Ausführung der
  Zustandskomponente wird verweigert;
- vorgeschlagenes Konto tu1nz-trendwatch und StateDirectory
  /var/lib/tu1nz-trendwatch0700; keine Übernahme von /opt/trendwatch;
- descriptor-relative Dateien0600, exklusive Sperre, atomarer Austausch und
  fsync, Ablehnung von Links, fremden Eigentümern/Gruppen, ACLs und Pfadtausch;
- vier datumsbezogene Kontextkennungen, HTML-sichere Formatierung;
- vor dem Transport ein dauerhaftes UNCERTAIN; nur bestätigter Erfolg wird SENT;
  ein Timeout/Abbruch wird NICHT automatisch erneut gesendet;
- fehlende Slots werden erkannt. Ohne serverseitige Idempotenz lässt sich nach
  einem Verbindungsabbruch nicht allgemein beweisen, ob Telegram zugestellt hat.
  UNCERTAIN ist ausdrücklich keine behauptete erfolgreiche Zustellung;
- reine Service-Kandidatentexte mit festem Programmziel, LoadCredential,
  NoNewPrivileges, leerem Capability-Satz, restriktivem Dateisystem und
  AF_UNIX/AF_INET/AF_INET6 für DNS/TLS.

Die Implementierung besitzt noch keinen installierbaren Live-Transport-/
Credential-Bindungsadapter. Testtransporte sind injiziert und versenden nichts.
Die Service-Kandidaten sind daher **keine installierbaren Unitdateien**; das
angegebene ExecStart-Ziel wurde nicht installiert. Seine Bindung und eine
gegebenenfalls nötige lesbare Titelveröffentlichung hängen von der offenen
Verbraucheranalyse ab. Ein syntaktischer Unit-Texttest ersetzt kein abschließendes
systemd-analyze verify der späteren vollständigen Installationskapsel.

Der bestehende Affiliate-Formatter wurde zweimal unprivilegiert und ohne
Netzwerk/Post aufgerufen. Beide Ergebnisse passen zum nachgewiesenen remix-
Label, den beiden erlaubten Produktschlüsseln und dem bisherigen URL-Aufbau.
Die Formatierung erfindet keine Live-Trenderkennung: der bisherige Haupttitel
stammt aus festen Daten. Das ungenutzte zusätzliche Fetch-Ergebnis darf nicht
als verlorene dynamische Nachrichtenfunktion dargestellt werden.

`scripts/tu1nz_codex_broker_v4.py` enthält feste Diagnosekomponenten:
status, containers, journal-counts, security-backup. Exakte Ein-Argument-Grammatik,
NOPASSWD mit NOSETENV nur für diese Kennungen, keine Wildcards. Feste Programme,
Umgebung, Units, Container und Sicherungsziele; keine frei gewählten Befehle,
URLs, Pfade oder Neustarts. Docker-Env/Logs und Journalnachrichten werden nicht
an chatops zurückgegeben. Private additive Sicherung und Audit liegen später
in einem root-eigenen0700-Baum, Dateien0600. Start aus dem Repository wird
abgewiesen; benötigt werden der genaue Installationspfad und ein root-geschütztes
Manifest mit Programmprüfsummen. Diese wurden nicht installiert.

Dies ist noch nicht die vollständige geprüfte Migrationskapsel. Installer,
phasenübergreifender Watchdog, Rollbackadapter, SSH-Abnahme und alle
Installations-Failure-Injections sind **nicht abgeschlossen**. Eine Behauptung,
die zweiphasige Gesamttransaktion sei offline vollständig bestanden, wäre falsch.
Die alten Modelle mit polkit_replace dürfen dafür nicht wiederverwendet werden;
Polkit und trendwatch-restart für daniel bleiben ausgenommen.

## Agentmode und weitere Privilegienträger

Der laufende tu1nz_agentmode.service ist chatops und trägt weiterhin Docker-GID987.
Er startet das root-eigene tu1nz_sync_all.sh --loop. Im Code keine Docker-
Abhängigkeit; die erste Schleifeniteration erfolgt unmittelbar beim Start.
Sie synchronisiert das Docs-Repository mit fetch/reset, schreibt Status und
Checksummen, nimmt flock und kann bei verändertem Übergangsschlüssel benachrichtigen.
Ein sofortiger Restart ist daher nicht gleichbedeutend mit wirkungslosem Neustart.

Der belegte Zustand CONTROL_LOCAL_STATE_INVALID/DOCS_SYNCED bleibt ein eigener
Altbestand. Der detached Checkout bleibt unverändert. Eine künftige
Pausen-/Wiederaufnahmebehandlung muss Unit, Quelle, Sperre, Zustandsdateien,
Notification-Key und Docs-Stand sichern sowie unvorhergesehene Übergänge
verweigern. Sie darf nicht pauschal chatops-Prozesse töten oder den Control-Branch
wechseln. Ein fertig getesteter Live-Wiederanlauf wird hier nicht behauptet.

Zusätzlicher Befund: Mommyramonas Hauptprozess läuft effektiv mit UID0 und
Capabilities; /opt/telegram_chatbot ist chatops-eigen und nach /app beschreibbar
gebunden. Jellyfins Init läuft ebenfalls UID0 und besitzt beschreibbare
chatops-eigene Mounts; daraus folgt nicht, dass sein eigentlicher Medienprozess
root ist. Die /proc/.../fd-Verzeichnisse beider Root-Prozesse sind für chatops
nicht lesbar. Es wurde kein Container ausgeführt, neu gestartet oder verändert.
Die tatsächlichen offenen Writer müssen getrennt von bloßen Mount-/UID-Indizien
bewertet werden; Abwesenheit in einer Momentaufnahme beweist keine generelle
Schreibfreiheit. Keine stillschweigende Container-Ausnahme vom Zielmodell.

## Warum genau eine privilegierte Lesung erforderlich bleibt

Folgende geschützte Dateien sind unprivilegiert nicht lesbar und enthalten laut
files.json auch in V3 keine Inhaltsbelege:

- /var/spool/cron/crontabs/root und chatops;
- /usr/local/bin/aide_daily.sh;
- /usr/local/bin/backup_notify.sh;
- /usr/local/bin/doku_agent_health.sh;
- /usr/local/bin/tu1nz-ape-notify-core.

Die normal lesbare /etc/crontab und die Cron-Verzeichnisse werden ergänzend im
gleichen Sammler erfasst; ihre Lesbarkeit ist nicht der Freigabegrund.

Ohne die geschützten Daten sind die YouTube-Produzenten und weitere Root-Schreibwege nicht
vollständig abgedeckt. Ein endgültiger Zielpfadsatz, Funktionsersatz und exakter
Rollback dürfen deshalb noch nicht festgeschrieben werden. Das ist eine
nachgewiesene Zugriffs-/Beleglücke, keine Bitte um eine Routinefreigabe.

`scripts/tu1nz_privilege_readonly_v4.py` und der reine Launcher-Generator sind
vorbereitet und getestet. Der eine spätere sudo-Aufruf führt ausschließlich
den im Speicher vor und nach sudo SHA-256-geprüften Sammler aus. Er lädt kein
Repositorymodul als root. Zusätzliche Argumente werden verweigert.

Ausgabe ausschließlich unter /var/lib/tu1nz-privilege-audit-v4, mit geprüften
root-eigenen, nicht fremdbeschreibbaren Eltern ohne Symlinks/ACL-Abweichung.
Verzeichnisse0700, Dateien0600; keine vorhandenen Fremddateien überschreiben.
Keine Root-Ausgabe in den bisherigen chatops-eigenen privaten Nachweisbaum.
Rohdateien bleiben root-only. stdout enthält nur bereinigte Metadaten,
Prüfsummen, bekannte Referenzen und Abschnittsstatus, keine Quellzeilen,
Tokenwerte, Umgebungswerte oder Journalinhalte.

Die Abschnitte sichern sofort atomar und unabhängig. Fehlerklassen statt
Fehlermeldungs-Rohdaten; monotone Start-/Endzeit; erhaltene Teilergebnisse und
INCOMPLETE-Manifest bei Unterbrechung. Exit0 vollständig erhoben,2 Teilergebnisse,
3 unsicherer Start. Der einzige externe Befehl ist festes systemctl show mit
20-Sekunden-Timeout. Keine Dienstaktion, Dockeraktion, Nachricht oder Auditregel.
Offene privilegierte Dateideskriptoren werden nur anhand von Metadaten erfasst.
COMPLETE bezeichnet den Sammellauf, nicht die Sicherheitsfreigabe der Migration.

Sammler-SHA256:
`15d0a3209928b455853aad64b33c4d8cf8e1d5ce976ada94b0e0ceb11ee49af4`.

## Validierung / Sicherung

120 gezielte Tests bestanden: bisherige78 plus42 neue Komponenten-/Sammlertests.
Geprüft sind u.a. vier Slots, Duplikate, fehlende Slots, fehlende Credentials,
Netzfehler per Fake-Transport, falsche Dateien/Rechte/ACLs, Links, Pfadtausch,
Unterbrechung, parallele Sperre, Argument-/Umgebungsangriffe, Ausgabeunterdrückung,
Teilmanifest und Hash-Drift vor sudo. Keine echten Telegram-/YouTube-Requests.
Dies sind keine erfolgreichen Installations-/Live-Rollbacktests.

Der neue sudoers-Entwurf wurde zusammen mit dem exakten historischen
Entfernungskandidaten und allen erhaltenen Includedateien unprivilegiert mit
visudo geprüft: Exit0, stderr leer. Private Fixture:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/privilege-v4-visudo-jjx0zynt.
Ein erster Harness-Versuch stoppte vor visudo wegen einer zu groben Zählung des
Includedir-Pfades inklusive Kommentar. Der erfolgreiche Versuch ersetzt nur
die eine exakte @includedir-Direktive; keine produktiven sudoers-Bytes geändert.

Frischer privater Metadatenbeleg:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/privilege-v4-preparation-20260927T125845Z/evidence.json
SHA256:7e5bdcf048dd561f830c80d2191e05373f1f9dd21335b42eac5685a48e0dc59a.
Bearbeitete neue Komponenten wurden vor weiteren Änderungen mit Zeitstempel
privat gesichert. Historische Dateien wurden nicht überschrieben.

Aktueller Control-Checkout: clean/detached7c634d3b82572e8459d51c69f04dce82c624d766.
Die bereits bekannte S8-/S10.1-Drift ist im neuen Beleg gebunden; ein späterer
Installer muss nochmals unmittelbar vor Aktivierung sichern und unbekannte
Drift verweigern. V3 bleibt historisch und darf kein aktuelles Restoreabbild
ersetzen. Eine belastbare maximale Dienstunterbrechung ist erst nach Abschluss
der fehlenden Abhängigkeiten und des vollständigen Transaktionsadapters möglich.

Nächster freigegebener Schritt nach persönlicher Bereitschaft: ausschließlich
der eine lesende Nachsammler. Kein Migrations-, Watchdog- oder Aktivierungsstart.
