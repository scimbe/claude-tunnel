# Evaluation: Tunnel-Roundtrip-Latenz (Parameterstudie, M16)

Auswertung der Messreihe aus `latency.csv`, reproduzierbar erzeugt per
`scripts/sweep.sh` (Messung), `scripts/plot.sh` (Abbildungen) und
`scripts/tabulate.py` (Tabellen) — alles Docker-only. Diese Studie ersetzt die
Demonstrations-Messung aus M6: sie läuft am **fertigen Produkt** über alle drei
Betriebsarten und mit statistisch belastbarem $n$.

## Versuchsaufbau

- **Testbett:** Docker-Compose-Topologie (`docker/docker-compose.yml`) mit
  Edge, Agent, Origin und Client auf einem statischen Netz (10.5.0.0/24).
- **Impairment:** `tc netem` auf der Edge-Egress (`netem-entrypoint.sh`),
  konfiguriert über `EDGE_DELAY` / `EDGE_LOSS`; die PoW-Schwierigkeit über
  `EDGE_POW_DIFFICULTY` (hier fest 8).
- **Betriebsarten (`SWEEP_MODES`):** `single` (One-shot-Noise), `stream`
  (voll-duplexer Streaming-Pfad, M9) und `udp` (Datagramm-Pfad, M10, gegen einen
  fixed-port UDP-Echo-Origin). Der Client misst je Bedingung $n=20$ vollständige
  Roundtrips mit **frisch aufgebauter QUIC-Verbindung** (Dial → PoW-Rendezvous →
  Noise-Handshake → Tunnel → Echo-Verifikation).
- **Matrix:** Modus $\in$ {single, stream, udp} $\times$ Verzögerung
  $\in \{0, 20, 50\}$ ms $\times$ Verlust $\in \{0, 2\}$ % (18 Bedingungen).
- **Statistik:** je Bedingung Mittel, Stichproben-Standardabweichung, 95%-KI des
  Mittels ($1{,}96\,\sigma/\sqrt{n}$) sowie p50/p95/p99 (Nearest-Rank).

Ergebnistabelle: `results-table.md` / `results-table.tex`
(`\label{tab:latency}`). Abbildungen: `latency-vs-delay.png`,
`latency-vs-loss.png`, `latency-by-mode.png`.

## Beobachtungen

1. **Baseline (0 ms, 0 %):** Mittel **8–9 ms** über alle Modi (single 8.8,
   stream 8.0, udp 8.3 ms) mit engem KI (±0.3 ms). Das ist der Eigenanteil des
   Tunnels ohne Netzverzögerung: QUIC-Handshake, PoW-Rendezvous und der
   Mehrsprung-Relay Client→Edge→Agent→Origin.

2. **Latenz skaliert linear mit der Edge-Verzögerung.** Für `single` (0 ms →
   8.8, 20 ms → 131.1, 50 ms → 312.4 ms) ergibt sich näherungsweise
   $\text{RT} \approx 8.8 + 6.1 \cdot d$ ($d$ = einseitige Edge-Verzögerung in
   ms). Der Faktor ~6.1 spiegelt wider, dass ein Anwendungs-Roundtrip die
   verzögerte Edge-Egress **mehrfach** quert — QUIC-Verbindungsaufbau,
   PoW-Rendezvous-Austausch und der Hin-/Rückweg des Relay-Pfads. Da pro
   Iteration frisch gewählt wird, trägt der Handshake ein festes Vielfaches der
   RTT bei. Bei 0 % Verlust sind die KI eng (±2–5 ms), der lineare Zusammenhang
   also gut aufgelöst.

3. **Paketverlust trifft fast ausschließlich den Tail, nicht den Median.** Bei
   2 % Verlust bleibt der p50 praktisch unverändert (z. B. single 20 ms:
   129.8 → 129.7 ms), während der p99 explodiert (149.6 → **1153.7 ms**, Faktor
   ~7.7). Ursache ist der QUIC-Probe-Timeout (PTO): geht während des Handshakes
   ein Paket verloren, wartet die Verbindung ein RTT-proportionales Timeout ab,
   das einzelne Iterationen um Hunderte ms verlängert. Das zeigt sich auch in
   der großen Streuung (single 20 ms/2 %: $\sigma \approx 313$ ms, KI ±137 ms):
   die Verteilung ist stark rechtsschief.

4. **Die Betriebsart ist bei 0 % Verlust nicht latenzbestimmend.** In
   `latency-by-mode.png` überlagern sich single/stream/udp nahezu deckungsgleich
   — die Latenz ist **verzögerungsdominiert**, nicht transport-dominiert. Die
   Framing-Unterschiede (One-shot vs. Streaming-Pump vs. Datagramm) fallen gegen
   die mehrfach gequerte Netz-RTT nicht ins Gewicht.

5. **Unter Verlust deuten sich Modus-Unterschiede an, sind bei $n=20$ aber nicht
   signifikant.** Die Punktschätzer streuen (z. B. bei 20 ms/2 %: udp-Mittel
   182.3 vs. single 238.9 ms), doch die 95%-KI überlappen deutlich
   (±99.8 bzw. ±137.0 ms). Angesichts der schweren Tails lässt sich aus diesem
   Lauf **kein statistisch belastbarer Modus-Effekt unter Verlust** ableiten;
   dafür wäre ein deutlich größeres $n$ nötig.

## Einordnung und Limitierungen

- Das Impairment wirkt **nur auf der Edge-Egress**, nicht symmetrisch und nicht
  auf Agent/Client — die absolute Latenz ist eine untere Schranke für eine voll
  bidirektional verzögerte Strecke.
- Der **Frisch-Dial pro Iteration** überzeichnet den Handshake-Anteil bewusst
  (Worst Case Verbindungsaufbau); ein Keep-Alive-Datenpfad läge niedriger.
- $n=20$ löst den Mittelwert bei 0 % Verlust eng auf (schmale KI), ist für den
  schweren Tail unter Verlust aber knapp — die p99-Werte und der Modus-Vergleich
  unter Verlust sind entsprechend mit Vorsicht zu lesen.
- **PoW-Schwierigkeit:** dieser Lauf fixiert `EDGE_POW_DIFFICULTY=8`. Die
  Sweep-Achse `SWEEP_POWS` erlaubt eine gezielte Schwierigkeitsstudie (Einfluss
  auf die Rendezvous-/Handshake-Phase); sie ist reproduzierbar, wurde hier aber
  nicht ausgefahren.
