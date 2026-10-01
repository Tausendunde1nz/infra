# Enger n8n-Workflowexport ohne Root und ohne n8n-Initialisierung

Basis 93954ea; expliziter Auftrag erlaubt einen ausschließlich lesenden Export.
V12-Rohdaten wurden nicht erneut erhoben. n8n Public- und REST-Lese-API liefern
für den einzigen betroffenen Workflow HTTP 401. Kein angemeldeter n8n-Tab
vorhanden; Browserautomation zusätzlich durch Extension-UI blockiert.

Installierter n8n-Code 1.114.3: export:workflow erbt BaseCommand.init mit
DbConnection.migrate, AuthRolesService.init und Telemetrie. Dieser CLI-Pfad
wird wegen möglicher Schreibwirkungen ausdrücklich nicht ausgeführt.

Alternative: der explizit autorisierte einzelne Workflowexport wird als
bestehender n8n-Dienstbenutzer UID/GID 1000 über docker exec -i node - gelesen.
Kein root, kein sudo, kein anderer Benutzer, keine neue Mount-/Netzwerkverbindung.
Nur der vorhandene SQLite-Treiber 5.1.7 wird geladen, keine n8n-Initialisierung.
Fester Workflow ptNQ8rpGMyk1zGx3; keine Credential- oder Execution-Tabelle.
SQLite OPEN_READONLY|OPEN_URI|OPEN_PRIVATECACHE, mode=ro, immutable=1,
query_only=ON und trusted_schema=OFF. Nichtleeres WAL/Rollbackjournal verweigert
diesen Weg. Symlinks, falscher Eigentümer, Hardlinks, falscher Workflowstatus,
unbekanntes Schema und Datenbankdrift verweigern den Export. Datenbank wird
nur in RAM gehasht, niemals vollständig gespeichert. Vorher-/Nachher-Hash und
Metadaten müssen übereinstimmen. Dies ersetzt keinen Root-Leser und startet
keine Anwendung, Workflowausführung, Migration oder Telemetrie.

Der unveränderte JSON-Export genau eines Workflowdatensatzes wird direkt aus
dem Prozess-Pipe in eine neue private Datei 0600 unter Verzeichnis 0700 auf
dem Mac geschrieben. Keine Rohwerte erscheinen in Toolausgaben, Git oder Logs.
Nur redigierte Ableitungen werden geprüft und versioniert. Zehn Offline-Fälle
mit Fake-Dateisystem/SQLite bestehen: Erfolg, WAL, Symlink, Owner, Drift,
Open-Fehler, View, fehlender Workflow, inaktiv und falsche UID.

n8n ist allein in n8n_n8n_default (172.26.0.2), Mommyramona in anderen Netzen;
ein gemeinsamer Service-DNS-Pfad ist derzeit nicht belegt. Keine Verbindung
wird hinzugefügt. V11-Live-Aktivierung bleibt getrennt.
