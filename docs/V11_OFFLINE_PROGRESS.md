# V11: n8n abgeschlossen, neue Offline-Bausteine, Aktivierungsreife nicht erreicht

Stand 2026-10-01; Fortsetzung von `93954ea`, nach den beiden Exporter-Commits
`f062d725` und `b502194`. Kein weiterer privilegierter Sammler, keine Live-Migration,
kein Workflow-Run, keine Workflowänderung, kein Container-Recreate, kein Watchdog
und kein PR. Ein Aktivierungsbefehl wird aus diesem Zwischenstand nicht erzeugt.

## Abgeschlossener Netzwerkvertrag

Die sieben Marker sind einzeln in `N8N_MARKER_SEMANTICS.json` gebunden und als
`NON_NETWORK_EXPRESSION` klassifiziert. Ihre Herkunft und Wirkung stehen in der
Markdown-Begleitdatei. Keine direkte Container-IP-/MAC-Abhängigkeit und keine
notwendige n8n-Änderung. Die enge semantische Zulassung bindet Workflowversion,
Feldpositionen und Knoten-/Verbindungs-/URL-Hashes; Drift wird nicht akzeptiert.

`V11_FINAL_NETWORK_CONTRACT.json` legt Fall A fest: dynamische Docker-IP/MAC,
beide bisherigen Netze und Alias-Mengen, Default-Route über `tausendunde1nz_net`,
Hostport `8081` zu intern `8080`, durch Docker aktualisierte DNAT-Regeln. Keine
manuelle NAT-Rückspielung. Die Nonroot-Kandidatenprojektion enthält ausschließlich
UID/GID `20001:20001`, CapDrop ALL, NNP, read-only Rootfs und read-only Code-Bind.
Der vorhandene V12-NAT-/AppArmor-Nachweis bleibt unverändert maßgeblich.

## Neue Offline-Bausteine und Grenzen

Der neue Ordner `scripts/privileged_v11_offline` enthält unabhängig entwickelte
Vorbereitung. Es gibt keinen Installations-/Aktivierungslauncher. Die Module
wurden als chatops beziehungsweise lokal getestet und nicht als root ausgeführt.

| Baustein | Verifiziert | Noch keine Behauptung |
| --- | --- | --- |
| Broker | Drei feste Nur-Lese-Operationen, exakte Argumente, feste Programme/Umgebung, Hash-/Pfadprüfungen, begrenzte Ausgabe/Laufzeit, bereinigte Antworten | Keine installierte sudo-Regel, kein Produktionsbroker |
| Transaktionskoordinator | Dauerhaft atomarer Zustand, Lock, monotones Budget, Sicherungs-/Checkpoint-Protokoll, 13 geordnete Phasen, Fail-closed ab Authority-Seal | Fake-Host-Tests ersetzen keinen implementierten und geprüften Produktionsadapter |
| Trendwatch-Ersatz | Hashgebundene Entfernung genau zweier sudo-Aufrufe; Unit-Projektion auf chatops, keine Telegramausführung | Keine geänderte Unit, kein Timerlauf, keine gespeicherte Kopie des produktiven Geheimniswerts |
| Dokumentrenderer | Synthetische Markdown-Datei als UID 1001 erfolgreich zu HTML/PDF gerendert, atomare Artefakte | Keine produktive Dokumenterzeugung |
| Daten-Publisher | Feste Pfade/Dateitypen, Owner-/Modus-/Hashprüfung, Datenkopie statt root-Interpretation, differenzieller Rollback | Keine Root-Installation oder systemd-Verknüpfung |

Der Produktionsadapter für alle Phasen, das neue Root-Bootstrap/Staging, der
unabhängige Watchdog, frische SSH-Clientnachweise und die vollständige gemeinsame
Migration/Rollback-Probe sind noch nicht integriert. Die Zustandsmatrix weist
sie ausdrücklich als offen aus. Diese Komponenten dürfen nicht durch einen
wahr gesetzten Prüfwert oder den erfolgreichen 108-Schritte-Lauf ersetzt werden.

Der Koordinator setzt vor Watchdog-Abbruch `COMMIT_RECORDED`, nachdem alle
Abschlussprüfungen bestanden sind. Nach einem Absturz wird ausschließlich der
kontrollierte Watchdog-Abbau wiederholt, keine Mutation und keine Wiederöffnung
entzogener Privilegien. `COMPLETED` folgt erst nach verifizierter Deaktivierung.
Der Broker protokolliert einen nicht verifizierten Aufruf als `unverified`, nicht
als bestätigten chatops-Aufruf; ein separater Regressionstest deckt dies ab.
Die 52 Vorher-/Nachher-Fehlerinjektionen über 13 Phasen prüfen den Protokollkern
mit einem Fake-Host, nicht reale systemd-, sudo- oder Docker-Mutationen.

Beim Publisher wurde ein Fehler des neuen Entwurfs korrigiert: eine spätere
Refused-Exception durfte einen früheren Dateiaustausch nicht am Rollback vorbei
zurücklassen. Jetzt werden nur eigene, noch identische Schreibresultate
zurückgenommen. Fremde Änderungen bleiben erhalten und führen zum Konflikt.
Nach fehlgeschlagenem Paar-Austausch bleibt die eindeutige PDF-Version als
Nachweis erhalten. Eine Rückkehr zur alten Inode wird nicht behauptet.

Der synthetische Renderer benötigt auf diesem Host rund 60 Sekunden. Das
ursprüngliche 30-Sekunden-Limit wurde nach dem isolierten Timeout auf begrenzte
120 Sekunden angepasst. Der geprüfte eigentliche Worker benötigte 60,172 Sekunden.
Der bestehende DokuKernel-Hook referenziert ein fehlendes Manifest; das ist ein
vorbestehender, bereits vom alten Build als Warnung behandelter Zustand. Keine
stille Rekonstruktion oder Behauptung eines erfolgreichen DokuKernel-Hooks.

## Aktuelle Laufzeitabweichung – Agentmode

Die V11-Baseline vom 2026-09-30 16:53:40 UTC führte
`tu1nz_agentmode.service` als active/running mit PID 1389949. Aktuell ist die Unit
inactive/dead, MainPID 0, weiterhin enabled. ExecMainCode 2 und ExecMainStatus 15
belegen Beendigung durch SIGTERM um 2026-09-30 22:19:16 UTC, entsprechend
2026-10-01 00:19:16 Europe/Berlin. systemd meldet Result=success und anschließend
Deactivated successfully. Die Unit ist bytegleich; keine Drop-ins, kein offenes
daemon-reload. Kein Neustart durch diesen Auftrag.

Die gezielte Journalabfrage um den Zeitpunkt enthält Deaktivierung und
Ressourcenabrechnung, aber keinen belegten Initiator. Eine zweite Abfrage des
30-Sekunden-Fensters wertete nur Metadaten geschlossener Klassen aus; keine
Nachrichten, sudo-Kommandos, Tokens oder Nutzinhalte wurden gespeichert.
Beabsichtigte Abschaltung und Fehlerzustand sind damit nicht unterscheidbar.
Die Abweichung wird weder als neuer Sollzustand übernommen noch repariert.
Der einzige referenzierte lokale Programmeinstieg ist `tu1nz_sync_all.sh`;
die eng begrenzte Strukturprüfung enthält keinen SIGTERM-/Kill-Aufruf und
keinen Agentmode-Zustandspfad. Sie belegt keinen Abschaltungsinitiator.
Daniels konkrete Einordnung dieser Abschaltung ist angefragt; keine allgemeine
Ausführungsfreigabe und keine Bestätigung mit „Fertig“.

## Tests und unveränderte Nachweise

376 gezielte Python-Tests bestehen unter Linux: neuer Kern 57, n8n-Zulassung 10,
V11 70, V12 53, V9 130, V10 56. Die vorausgehenden 56 Kernfälle bestanden zusätzlich lokal; der ergänzte Auditfall wurde unter Linux geprüft. Elf
kontrollierte JavaScript-Exporterfälle bestehen ohne Produktionsdatenbank.
Der JS-Test wird explizit über seine exportierte `test(source)`-Funktion aufgerufen;
ein bloßer Aufruf der Bibliotheksdatei ist kein Testnachweis.

Alle 108 vorhandenen Workflow-Schritte liefen von Schritt 1 in einem neuen
isolierten Checkout mit Exitcode 0. Zwei optionale Anwendungssimulationen in
Schritt 100 bleiben wegen fehlenden separaten Application-Checkouts skipped;
sie werden nicht als bestandene Anwendungstests dargestellt. Logs und Hashes
liegen im privaten Ergebnisverzeichnis, dessen Referenz in der JSON-Datei steht.

701 gebundene Dateien, alle 42 Hardening-Dateien, 1125 historische Nachweise und
30 V9-Quellen sind bytegleich. `1cf0d79` bleibt Vorfahr. Der detached Checkout ist
sauber und unverändert auf `9b383960291da469671c3888cfa4fdcc3c33cf01`.
Mommyramonas vollständiger semantischer Baseline-Vertrag stimmt weiterhin,
Container-ID, PID und Neustartzähler werden im privaten Nachweis festgehalten.
Die Agentmode-Laufzeitabweichung ist ausdrücklich von Bytegleichheit zu trennen.

## Vertraulichkeit und nächster Zustand

Keine privaten Sicherungen, Workflow-Rohdaten oder produktiven Secretwerte im
Commit. Der bereits gemeldete versehentliche Trendwatch-Token in einer
Toolausgabe ist in `N8N_MARKER_SEMANTICS.md` ohne Wert dokumentiert. Keine
Tokenrotation oder Sperrung im Rahmen dieses Auftrags vorgenommen.

N8N_IDENTITY_BLOCKER_CLOSED; NETWORK_CONTRACT_FINAL;
V11_ACTIVATION_NOT_READY. Historische Launcher bleiben gesperrt. Keine neue
MacBook-Bereitschaft anfordern, solange Baseline und vollständige integrierte
Transaktion einschließlich Rollback nicht verifiziert sind.
