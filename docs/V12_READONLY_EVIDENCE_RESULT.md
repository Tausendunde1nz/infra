# V12 – Ergebnis des einmaligen geschützten Leselaufs

01.10.2026; Basis `b717dc478edb26477cb8acfc39633ad8d6ada8e6`.
Daniels aktuelle MacBook-Bereitschaft lag vor. Genau ein Root-Leselauf,
keine Produktionsänderung, kein Watchdog, keine Aktivierung.

## Nachweise und Schutzgrenzen

`/var/lib/tu1nz-evidence-v12-djrz_uun/public/manifest.json`:
`afbb25bdfb94756745af62fad283faa5fbd9eaaa71132d37391b2d3d611e657a`.
Alle sechs Abschnitte OK, Manifest COMPLETE; alle Artefakthashes geprüft.
COMPLETE bezeichnet ausschließlich die Sammlung, keine Migrationsreife.

Root-eigene Kopie, erwarteter Quellhash, isoliertes Python 3.12.3, Bytecode aus;
Bootstrapmarker gebunden. Root-Verzeichnis 0711, staging/private 0700,
Bootstrapmarker 0600, für chatops nicht lesbar. Öffentliche reduzierte Dateien
root:root 0644 unter 0755. Keine Datenbankkopie auf Datenträger, keine
Workflowinhalte, Credential-Werte oder Rohlogs in Git. JSON-Begleitdatei
bindet die redigierten Nachweise; die Nachweisdateien selbst bleiben privat.

## n8n: direkte Referenzen und verbleibende Grenze

Sieben Workflows geprüft. Zwei Fundstellen in einem inaktiven Workflow:
Containerport 8080 sowie Container-/Service-/Aliasname
`telegram_bot_mommyramona`. Keine direkte IP-, MAC- oder Hostport-8081-Referenz
unter den ausgegebenen Treffern. Tatsächliche Nutzung ist durch Konfiguration
allein nicht bewiesen; inaktive Workflows können manuell ausgeführt werden.

Zehn dynamische Marker in inaktiven Workflows und sieben Marker in einem aktiven
Workflow bleiben unaufgelöst. Das beweist keine IP-/MAC-Abhängigkeit, schließt
sie aber auch nicht aus. Der Leser klassifiziert Expressions allgemein und
bewertet nicht, ob sie überhaupt netzwerkrelevante Parameter steuern.
Eine automatische Umdeutung aller Marker zu ungefährlichen Referenzen wäre
unbelegt. Ebenso wenig rechtfertigt dies statische IP-/MAC-Pins aus Vermutung.

Die geschützte Nginx-Datei enthält keine gesuchten Referenzen. Der bereits
belegte andere Proxy auf localhost:8081 bleibt davon unberührt.

## Produktiver NAT-Vertrag

Docker 28.5.1, iptables/ip6tables 1.8.10 mit nf_tables. Keine überschreibenden
Firewall-Backend-Flags in den geprüften dockerd-Argumenten oder daemon.json.
Das ist der Docker-iptables-Pfad über nft-Kompatibilität, kein Nachweis eines
nativen Docker-nftables-Backends.

IPv4 `nat/PREROUTING` und `nat/OUTPUT` (Priorität -100) springen nach DOCKER.
Dort genau eine passende DNAT-Regel: TCP 8081, Eingangsinterface ungleich
br-470c1e938747, Ziel 172.25.0.2:8080, nullbasierter Index 13, nft-Handle 69,
kein Regelkommentar. Die xt-DNAT-Erweiterung im nft-JSON wird durch den
passenden iptables-Auszug aufgelöst. Publishing 8081→8080 und Endpoint-IP
stimmen überein. Filterpfad: FORWARD → DOCKER-FORWARD → DOCKER-BRIDGE → DOCKER;
passende ACCEPT-Regel für Ziel 172.25.0.2:8080. Raw-PREROUTING (-300) enthält
Docker-konsistente Schutzregeln für beide aktuellen Containeradressen.
Zähler sind aus den Strukturprüfsummen entfernt.

Operative Zuordnung: Docker-Port-Publishing, keine zusätzliche manuelle oder
UFW-DNAT-Regel für dieses Ziel im gesammelten Befund. Historische Ersteller
werden nicht behauptet. Der vorhandene isolierte Recreate-Nachweis belegt
Docker-Aktualisierung bei IP-Wechsel. Produktive Regeln werden nicht manuell
nachgeladen, ersetzt oder im Rollback aus einem alten Kernel-Dump restauriert;
Docker muss sie aus dem wiederhergestellten Publishing und Endpoint erzeugen.

Keine passende IPv6-DNAT-Regel, keine Container-IPv6-Adressen, nur beobachteter
Listener 0.0.0.0:8081 (docker-proxy). Keine IPv6-Freigabe ergänzen. Vollständige
öffentliche Erreichbarkeit oder alle allgemeinen Filterregeln wurden in diesem
engen Lauf nicht erneut geprüft.

## AppArmor und Kontinuität

Der unveränderte vorbereitete Leser lief im selben Root-Aufruf. Aktiver Prozess:
`docker-default (enforce)`. Kernel-Profil-, Rohprofil- und Feature-Hashes sind
gebunden. Keine /etc/apparmor.d/docker[-default]-Quelldatei vorhanden. Ein
lesbarer wirksamer Policy-Export ist damit nicht bewiesen und wird gemäß
bestehendem V11-Vertrag nicht zum zusätzlichen Gate. Keine Policy verändert.
Mommyramonas abgefragte Identität, Image, Publishing und Netzwerke sind im
Vorher-/Nachhervergleich unverändert. Keine breite Live-Inventur behauptet.

## V11-Entscheidung und nächster notwendiger Nachweis

`CONSUMER_REVIEW_INCOMPLETE`; Aktivierung bleibt gesperrt. Der bestehende
Netzwerkprüfer verweigert die echten unvollständigen Verbraucherbefunde wie
vorgesehen. Alle 70 V11-Tests erneut bestanden. Der unmittelbar vorausgehende
Lauf aller 108 Workflow-Schritte gilt für die unveränderten Codebytes; zwei
optionale Application-Tests waren übersprungen. Dieser Abschluss ändert nur
zwei neue Dokumentationsdateien und schwächt keinen Prüfer ab.

NAT-Eigentümerschaft ist operativ ausreichend zugeordnet. Vor einer endgültigen
Wahl dynamischer Adressen muss eine gezielte statische Datenflussprüfung die
Expressions nach Ziel-/URL-/DNS-relevanten Parametern und ihren Abhängigkeiten
klassifizieren; keine Expression ausführen, keine Geheimnisse ausgeben.
Die vorhandenen reduzierten Ergebnisse enthalten diese Information nicht.
Deshalb kein weiterer Root-Lauf ohne dafür gesondert vorbereiteten, gebundenen
Leser, keine Vollständigkeitsbehauptung und keine endgültige V11-Transaktion.
Die weitere Root-Transaktion, vollständige Failure-Injection und Live-Zulassung
bleiben offen. Alte Launcher bleiben gesperrt. Spätere Live-Aktivierung verlangt
ein neues ausdrückliches MacBook-Fenster.
