# Mehrere Ausdruckgruppen (Küche, Theke, Bar)

## Das Problem

OrderAssist weist jedem Drucker eine **Ausdruckgruppe** zu. Ein Drucker wird
dort ausschließlich über seine **IP-Adresse** identifiziert – der Port ist
fest 9100 und lässt sich nicht ändern.

Daraus folgt: **Zwei Drucker brauchen zwei IP-Adressen.** Man kann sie nicht
über zwei Ports auf derselben IP unterscheiden.

BonBridge kennt deshalb zwei Wege.

## Weg A: Ein BonBridge-Gerät pro Drucker (einfach)

Jeder Drucker bekommt seinen eigenen Pi Zero 2 W. Nichts weiter zu tun –
jedes Gerät hat von Haus aus eine eigene IP.

| Vorteile | Nachteile |
|---|---|
| Einfachste Einrichtung | ~50 € pro Drucker |
| Ausfall betrifft nur einen Drucker | Mehr Geräte, mehr Netzteile |
| Kurze USB-Wege zum Drucker | Mehrere Weboberflächen |

Das ist die empfohlene Variante für zwei bis drei Drucker an verschiedenen
Orten (Küche und Theke liegen selten nebeneinander).

## Weg B: Ein Gerät, mehrere IP-Adressen (elegant)

Ein Raspberry Pi 4 (oder x86-Rechner) bedient mehrere per USB angeschlossene
Drucker. Jeder Drucker bekommt eine **zusätzliche IP-Adresse** auf derselben
Netzwerkkarte, und BonBridge bindet den jeweiligen Listener nur an diese
Adresse.

```
                      ┌── USB ──▶ Drucker Küche  ← 192.168.1.51:9100
Pi 4 ── LAN ──────────┤
 (192.168.1.50)       └── USB ──▶ Drucker Theke  ← 192.168.1.52:9100

  Weboberfläche: http://192.168.1.50:8080/
```

### 0. Die Drucker physisch anschließen

Bevor irgendetwas konfiguriert wird, müssen beide Drucker gleichzeitig am
Gerät hängen und erkannt werden.

**Stromversorgung – der wichtigste Punkt.** Jeder Bondrucker braucht sein
**eigenes 24-V-Netzteil**. Der Raspberry Pi versorgt keinen einzigen Drucker.
Der Pi selbst braucht bei mehreren USB-Geräten ein kräftiges Netzteil:

| Gerät | Netzteil für den Pi |
|---|---|
| Pi Zero 2 W | 5 V / 2,5 A |
| Pi 3 | 5 V / 2,5 A |
| Pi 4 / Pi 5 | Original-Netzteil (5 V / 3 A bzw. 5 V / 5 A) |

Wenn in der Übersicht unter „Warum?" **Unterspannung** auftaucht, ist das
Netzteil oder das Kabel zu schwach – das äußert sich sonst als sporadisch
verschwindende Drucker.

**Anschlussarten:**

```
Variante 1 – direkt (bis zu 2 Drucker am Pi 4/5)

   Pi 4  ┌── USB-A ──── USB-B ──▶ Drucker Küche   (eigenes 24-V-Netzteil)
         └── USB-A ──── USB-B ──▶ Drucker Theke   (eigenes 24-V-Netzteil)

Variante 2 – mit aktivem USB-Hub (ab 3 Druckern, oder beim Pi Zero)

   Pi ── USB ──▶ [ aktiver USB-Hub mit eigenem Netzteil ]
                        ├── USB-B ──▶ Drucker 1
                        ├── USB-B ──▶ Drucker 2
                        └── USB-B ──▶ Drucker 3
```

* Beim **Pi 4** die schwarzen USB-2.0-Ports bevorzugen, wenn ein Drucker
  zickt.
* Beim **Pi Zero 2 W** geht nur ein USB-Anschluss – für mehrere Drucker
  zwingend ein **aktiver** Hub (mit eigenem Netzteil), sonst bricht die
  Spannung ein.
* **Passive Hubs** sind die häufigste Fehlerursache bei mehreren Druckern.

**Prüfen, ob beide erkannt werden:**

```bash
bonbridge scan
```

Beide Drucker müssen mit eigener Zeile auftauchen. Bei zwei baugleichen
Geräten unterscheiden sie sich nur in der **Seriennummer** – die brauchst du
gleich:

```
usb     EPSON TM-T88V (04b8:0202)
        vendor_id_hex: 04b8
        product_id_hex: 0202
        serial: X3M4820015          <- diese Zeile
usb     EPSON TM-T88V (04b8:0202)
        serial: X3M4820099
```

> Zeigt `bonbridge scan` nur einen Drucker, ist es ein Hardware-Problem
> (Strom, Kabel, Hub) – kein Software-Problem. Erst weitermachen, wenn beide
> zu sehen sind.

## Der kurze Weg: BonBridge sucht die Adressen selbst

Ab 1.3.4 muss man die Zusatzadressen nicht mehr von Hand aussuchen und
anlegen. **Weboberfläche → System → „IP-Adressen für mehrere Drucker"**:

1. **„Freie IP-Adressen automatisch zuweisen"** einschalten und speichern.
2. **„Zuordnung vorschlagen"** drücken.
3. Die Tabelle **Drucker → Adresse** prüfen, bei Bedarf eine Adresse ändern.
4. **„Zuordnung übernehmen"**.

Erst Schritt 4 legt etwas an. Schritt 2 sucht nur und zeigt, **welcher Drucker
welche Adresse bekommen würde** — geändert wird dabei nichts. Das ist Absicht:
Eine neue Druckeradresse musst du danach im Kassensystem eintragen, und das
sollte nicht hinter einem einzelnen Knopfdruck passieren.

Beim Übernehmen wird **jede Adresse noch einmal geprüft**. Zwischen Vorschlag
und Bestätigung liegt menschliche Zeit — lang genug, dass jemand ein Handy
einschaltet.

Unter der Tabelle steht zusätzlich **jeder Drucker mit seiner aktuellen
Adresse**, auch die, die noch auf `0.0.0.0` stehen. So lässt sich die Liste
nicht als „alle haben eine Adresse" missverstehen.

Über SSH geht dasselbe:

```bash
sudo bonbridge aliases              # nur suchen und anzeigen
sudo bonbridge aliases --assign     # suchen und zuweisen
sudo systemctl restart bonbridge
```

### Wie „frei" geprüft wird

Nicht per Ping – **per ARP, nach RFC 5227.** Der Unterschied ist
entscheidend: Ein Windows-PC beantwortet standardmäßig keinen Ping, benutzt
seine IP-Adresse aber selbstverständlich weiter. Eine Ping-Prüfung würde
genau diese Adresse als „frei" melden und beide Geräte lahmlegen. ARP kann
kein IPv4-Gerät verweigern und trotzdem im Netz arbeiten.

Gesendet wird eine ARP-Anfrage mit **Absenderadresse 0.0.0.0** – die Prüfung
beansprucht die Adresse also nicht, nach der sie fragt. Drei Anfragen je
Adresse, damit ein einzelner verlorener Broadcast eine belegte Adresse nicht
frei aussehen lässt. Antwortet jemand, merkt sich BonBridge die MAC-Adresse
des Antwortenden – daran unterscheidet es später „jemand anders hat sie
genommen" von „das ist unser eigener Alias".

Gesucht wird standardmäßig **vom oberen Ende des Subnetzes abwärts**, weil
DHCP-Bereiche dort am seltensten hinreichen. Ein fester Bereich lässt sich
eintragen: `192.168.1.240-192.168.1.250`.

### Was das nicht kann

Dass eine Adresse heute frei ist, sagt nichts über morgen. Liegt sie im
DHCP-Bereich des Routers, kann der Router sie später an ein Handy vergeben –
und dann verschwinden Bons, ohne dass irgendetwas kaputt aussieht.

**Deshalb: den benutzten Bereich im Router aus dem DHCP-Bereich herausnehmen.**
Das bleibt der einzige echte Schutz.

BonBridge prüft die vergebenen Adressen alle fünf Minuten nach. Antwortet
plötzlich eine fremde MAC-Adresse, erscheint das unter *Diagnose → Alle
Prüfungen* als Fehler mit der MAC des Eindringlings. Verhindern kann BonBridge
den Fall nicht – nur bemerken und benennen.

### Neustart, Konflikte, Rückgabe

* Die Aliase überleben einen Neustart: BonBridge merkt sich in `state.json`,
  was es angelegt hat, und legt es beim Start neu an – **nach erneuter
  Prüfung**. Ist die Adresse inzwischen von jemand anderem belegt, wird sie
  *nicht* wieder beansprucht, sondern aufgegeben; der Drucker fällt auf
  `0.0.0.0` zurück und druckt weiter, während der Konflikt gemeldet wird.
* Von Hand eingetragene Adressen werden nie angefasst. Freigeben lassen sich
  nur Adressen, die BonBridge selbst angelegt hat.
* **Bei nur einem Drucker passiert absichtlich nichts:** `0.0.0.0` antwortet
  ohnehin auf jeder Adresse des Geräts. Wer trotzdem eine eigene Adresse will,
  bestätigt die Rückfrage bzw. benutzt `--force`.

---

## Der manuelle Weg

Weiterhin gültig – und die richtige Wahl, wenn die Adressen aus anderen
Gründen fest vorgegeben sind.

### 1. Freie IP-Adressen wählen

Die zusätzlichen Adressen müssen

* im selben Subnetz liegen wie das Gerät,
* **außerhalb des DHCP-Bereichs** des Routers liegen (sonst vergibt der Router
  sie irgendwann an ein anderes Gerät),
* noch frei sein.

Prüfen:

```bash
ping -c1 192.168.1.51    # darf NICHT antworten
```

### 2. IP-Aliase einrichten

Der Installer bringt dafür eine systemd-Unit mit. Instanzname ist
`<interface>-<adresse>-<prefix>`:

```bash
# Netzwerkschnittstelle herausfinden
ip -o addr show scope global

sudo systemctl enable --now 'bonbridge-ip@eth0-192.168.1.51-24.service'
sudo systemctl enable --now 'bonbridge-ip@eth0-192.168.1.52-24.service'
```

Beim Pi Zero 2 W heißt die Schnittstelle meist `wlan0`:

```bash
sudo systemctl enable --now 'bonbridge-ip@wlan0-192.168.1.51-24.service'
```

Kontrolle:

```bash
ip -4 -o addr show scope global
```

Die Aliase überleben einen Neustart, weil die Units aktiviert sind.

### 3. Drucker in BonBridge anlegen

Weboberfläche → **Drucker**:

1. **Geräte suchen** – beide USB-Drucker müssen erscheinen.
2. Für den ersten Drucker: Name `Küche`, *IP-Adresse für Port 9100* auf
   `192.168.1.51`, Anschluss übernehmen, speichern.
3. **Drucker hinzufügen** → Name `Theke`, `bind` auf `192.168.1.52`, das
   zweite Gerät übernehmen, speichern.

Alternativ direkt in `/etc/bonbridge/config.yaml`:

```yaml
printers:
  - id: kueche
    name: Küche
    enabled: true
    bind: 192.168.1.51
    transport:
      type: usb
      vendor_id: 0x04b8
      product_id: 0x0202
      serial: "X3M4820015"      # unterscheidet zwei baugleiche Drucker
    profile: TM-T88V

  - id: theke
    name: Theke
    enabled: true
    bind: 192.168.1.52
    transport:
      type: usb
      vendor_id: 0x04b8
      product_id: 0x0202
      serial: "X3M4820099"
    profile: TM-T88V
```

> **Wichtig bei baugleichen Druckern:** Zwei identische TM-T88V haben dieselbe
> Vendor/Product-ID. Damit die Zuordnung stabil bleibt, muss die
> **Seriennummer** eingetragen werden. `bonbridge scan` zeigt sie an. Ohne
> Seriennummer kann sich die Zuordnung nach einem Neustart vertauschen.

### 4. In OrderAssist eintragen

| Ausdruckgruppe | IP im Kassensystem |
|---|---|
| Küche | `192.168.1.51` |
| Theke | `192.168.1.52` |

Danach in OrderAssist unter **Drucker → Ausdruckgruppen definieren** die
Zuordnung vornehmen. Die Verteilung der Bestellungen macht OrderAssist selbst –
BonBridge liefert nur die Drucker.

| Vorteile | Nachteile |
|---|---|
| Ein Gerät, eine Weboberfläche, ein Update | Alle Drucker müssen per Kabel an einem Ort erreichbar sein |
| Günstiger ab zwei Druckern | Fällt das Gerät aus, stehen alle Drucker |
| Gemeinsame Diagnose und Support-Bericht | IP-Verwaltung im Router nötig |

## Mischbetrieb

Ein BonBridge-Gerät kann gleichzeitig USB-Drucker bedienen **und** einen
Netzwerkdrucker überwachen:

```yaml
  - id: bar
    name: Bar
    bind: 192.168.1.53
    transport:
      type: network
      host: 192.168.1.30    # Drucker mit eigenem UB-E04
      port: 9100
```

Sinnvoll, wenn man Statusüberwachung, Zwischenspeicherung und einen
gemeinsamen Support-Bericht auch für die Netzwerkdrucker haben möchte.
Wer das nicht braucht, trägt den Netzwerkdrucker im Kassensystem einfach
direkt ein.

## Grenzen

* **Ein Drucker, mehrere Gruppen:** kein Problem – das regelt OrderAssist,
  indem es denselben Drucker mehreren Gruppen zuweist.
* **Mehr als ~4 USB-Drucker an einem Pi:** möglich, aber dann auf
  Stromversorgung achten und einen aktiven USB-Hub verwenden.
* **Verschiedene Subnetze:** IP-Aliase funktionieren nur im selben Netz wie
  die Kassengeräte.
