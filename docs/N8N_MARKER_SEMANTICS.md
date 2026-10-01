# Sieben n8n-Marker: abgeschlossene Netzwerksemantik

Workflow `ptNQ8rpGMyk1zGx3`, Version `78a3f06a-99e6-45b9-afb7-33045a858ff0`,
aktiv; updatedAt `2025-10-24 19:38:35`. Privater unveränderter Einzelexport
SHA-256 `1a1300de0403cbf1c05a3dd2025dfa60217c32357d8b222c57b382c44c45405d`.
Keine Ausführung, Speicherung, Aktivierung oder Workflowänderung. Kein sudo.
Ausführung ausschließlich eines lesenden Exporters als Dienst-UID 1000;
DB-Vorher/Nachher-Hash gleich, kein nichtleeres WAL/Journal, keine DB-Schreiböffnung.
Der globale DB-Hash unterscheidet sich vom älteren V12-Lauf; er wird nicht als
Workflowversion verwendet. Die aktuelle Einzelversion und ihre Knoten/Verbindungen
sind separat gebunden. Keine Execution-Payloads oder Credentials gelesen.

## Einzelklassifizierung

Alle sieben V12-Marker sind `NON_NETWORK_EXPRESSION`. Ihre exakten technischen
Feldpfade, Node-IDs, Typen und Ausdruckshashes stehen in der JSON-Begleitdatei.

| Marker | Node-ID / Feld | Wertquelle und Wirkung |
| --- | --- | --- |
| 1 | Exec_BuildProduct / command | productSlug und promptText aus statischem Function_BuildPrompt; Argumente für festen lokalen Skriptpfad, anschließend Statusausgabe |
| 2 | Function_PrepareTelegram / functionCode | Vorgängerfelder slug, dir, timestamp, status, summary; erzeugt Nachrichtenkörper, keine URL |
| 3 | HTTP_TelegramNotify / bodyParameters.parameters[1].value | `$json.text`, ausschließlich HTTP-Body |
| 4 | HTTP_TelegramNotify / bodyParameters.parameters[2].value | `$json.parse_mode`, ausschließlich HTTP-Body; gespeicherter Parametername enthält eine Leerstelle (`parse _mode`), keine Korrektur im Auftrag |
| 5 | Function_LogFragment / functionCode | Vorgängerfelder productSlug/productDir; erzeugt lokale Logzeichenfolge |
| 6 | Exec_WriteLog / command | `$json.logText`; lokale Dateianfügung an festen Logpfad |
| 7 | ca0de873-8e62-4ffc-94d5-3043d9c828b6 / command | `$json.PRODUCT_DIR`; lokale Verzeichniswahl, ls-/du-Auswertung und Statusausgabe |

Der HTTP-Node selbst besitzt einen statischen externen Endpunkt:
`https://api.telegram.org:443/bot<redacted>/sendMessage`. Das n8n-Präfix `=`
ist vorhanden, aber keine Interpolation in der Zieladresse. Keine der sieben
Expressionen bestimmt Schema, Host, Port oder Pfad. Keine IP-/MAC-/8080-/8081-
oder Mommyramona-Namensreferenz in den geprüften dynamischen Parametern.
Kein Runtime-Controlled-Endpoint und kein belegter Mommyramona-SSRF-Pfad.

Die Werte stammen aus statischen Workflowwerten bzw. Vorgängerknoten,
nicht aus nachgewiesenen externen Endpoint-Vorgaben, Credentials oder Env.
Shell-Interpolation in ExecuteCommand bleibt ein eigenständiges Risiko:
eine Host-Allowlist löst keine Shell-Injection. Keine Ausnutzbarkeit behauptet,
keine Nutzlast getestet. Das referenzierte lokale Produktskript fehlt (ENOENT).
Dieser vorbestehende Funktionsbefund wird nicht repariert und nicht als
Mommyramona-Netzwerkblocker verwendet. Keine neue Workflowausführung zur Prüfung.

## Endgültiger funktionaler Netzwerkvertrag – Fall A

Dynamische IP und MAC, Endpoint-/Sandbox-IDs bleiben flüchtig. Keine statische
IPAM-Konfiguration und kein MAC-Pin. Docker-Publishing 8081→8080 ist stabil;
Docker aktualisiert die konkrete DNAT-Ziel-IP beim Recreate. Beide bisherigen
Netzwerke, Netzwerk-IDs, bestehende Alias-Mengen, DriverOptions, Gateway-Priorität,
Default-Netz tausendunde1nz_net, Image, unveränderte Portfreigaben und Mounts
bleiben Vertragsbestandteile. DNS, Hostport, internes Health, Proxy, Monitoring
und Routing werden nach Apply und Rollback geprüft. Keine manuelle NAT-Restauration.

n8n liegt allein in n8n_n8n_default, nicht in einem Mommyramona-Netz. Keine neue
Netzverbindung erforderlich. Inaktive direkte Namens-/8080-Referenzen aus V12
werden weiterhin durch den unveränderten Namens-/Aliasvertrag berücksichtigt;
sie rechtfertigen keine feste IP. Kein n8n-Patch oder Import erforderlich.

`semantic_admission.py` akzeptiert nur die explizit geprüfte Version mit ihren
Knoten-, Verbindungs- und URL-Hashes und exakt sieben Feldpositionen. Unbekannte
Expressionen, anderer Host, veränderte Version oder Hashdrift werden verweigert.
Das ist keine generelle Lockerung des V11-Prüfers. Der echte Export besteht
die enge Zulassung; zehn Offline-Testmethoden mit zusätzlichen Negativvarianten
bestehen. Der n8n-Identitätsblocker ist geschlossen; damit allein wird keine
Hostmigration freigegeben.

AppArmor-Nachweis und NAT-Rootnachweis aus V12 bleiben unverändert gebunden.
Kein weiterer Root-Sammler und keine historische Suche erforderlich.

## Vertraulichkeit

Der Rohworkflow verbleibt ausschließlich im lokalen privaten Nachweispfad
(Verzeichnis 0700, Datei 0600). Kein Rohworkflow, Token, Nachrichteninhalt oder
personenbezogener Wert wird committed. Beim späteren separaten Lesen des
bestehenden Trendwatch-Skripts gelangte ein eingebetteter Zugangstoken
versehentlich in eine Toolausgabe. Er wurde nicht in neue Dateien übernommen,
nicht wiederholt und nicht verwendet; keine Zugangssperrung ohne separaten Auftrag.
