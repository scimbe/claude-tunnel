# Evaluation: Tunnel-Roundtrip-Latenz (M6)

Auswertung der Messreihe aus `latency.csv`, erzeugt reproduzierbar per
`scripts/sweep.sh` (Messung), `scripts/plot.sh` (Abbildungen) und
`scripts/tabulate.py` (Tabellen) — alles Docker-only.

## Versuchsaufbau

- **Testbett:** Docker-Compose-Topologie (`docker/docker-compose.yml`) mit
  Edge, Agent, Origin (TCP-Echo) und Client auf einem statischen Netz
  (10.5.0.0/24).
- **Impairment:** `tc netem` auf der Edge-Egress (`netem-entrypoint.sh`),
  konfiguriert über `EDGE_DELAY` / `EDGE_LOSS`.
- **Messung:** `ct-client` im Bench-Modus (`CT_CLIENT_ITERATIONS`) misst je
  Bedingung $n=5$ vollständige Roundtrips (Dial → PoW-Rendezvous → Tunnel →
  Echo-Verifikation), jeweils mit **frisch aufgebauter QUIC-Verbindung**.
- **Matrix:** Verzögerung $\in \{0, 20, 50\}$ ms $\times$ Verlust $\in \{0, 2\}$ %.

Ergebnistabelle: `results-table.md` / `results-table.tex` (LaTeX,
`\label{tab:latency}`). Abbildungen: `latency-vs-delay.png`,
`latency-vs-loss.png`.

## Beobachtungen

1. **Baseline (0 ms, 0 %):** Mittel **6.8 ms** Roundtrip — der Eigenanteil des
   Tunnels (QUIC-Handshake + PoW-Rendezvous + Mehrsprung-Relay) ohne
   Netzverzögerung.

2. **Latenz skaliert linear mit der Edge-Verzögerung.** Aus den Mittelwerten
   (0 ms → 6.8, 20 ms → 92.7, 50 ms → 217.9) ergibt sich näherungsweise
   $\text{RT} \approx 6.8 + 4.2 \cdot d$ (mit $d$ = einseitige Edge-Verzögerung
   in ms). Der Faktor ~4.2 spiegelt wider, dass jeder Anwendungs-Roundtrip die
   verzögerte Edge-Egress **mehrfach** quert: Verbindungsaufbau
   (Client↔Edge-Handshake), PoW-Rendezvous und der Relay-Pfad
   Client→Edge→Agent→Origin und zurück. Da pro Iteration frisch gewählt wird,
   trägt der Handshake einen festen Vielfachen der RTT bei.

3. **Paketverlust wirkt proportional zur RTT.** Bei 0 ms und 20 ms ist 2 %
   Verlust im Mittel nicht messbar (6.8→6.9 ms, 92.7→92.2 ms; innerhalb der
   Streuung). Bei 50 ms steigt der Mittelwert um ~9 % (217.9→237.5 ms) und das
   p95 um ~18 % (260.4→306.5 ms): verlustbedingte Retransmits kosten umso mehr,
   je größer die zugrundeliegende RTT ist. Der Effekt zeigt sich primär im
   Tail (p95), nicht im Median (p50 ~unverändert bei 207 ms).

## Einordnung und Limitierungen

- Das Impairment wirkt in diesem Lauf **nur auf der Edge-Egress**, nicht
  symmetrisch und nicht auf Agent/Client — die absolute Latenz ist daher eine
  untere Schranke für eine voll bidirektional verzögerte Strecke.
- $n=5$ dient hier der **Demonstration der Mess-Pipeline**; die belastbare
  Evaluation (Kapitel Evaluation, M7.5) nutzt größere $n$ und eine breitere
  Matrix inkl. Bandbreitenbegrenzung (`SWEEP_RATES`).
- Der **Frisch-Dial pro Iteration** überzeichnet den Handshake-Anteil; ein
  Keep-Alive-Datenpfad läge niedriger. Beide Betriebsarten sind für die
  Evaluation relevant und über `CT_CLIENT_ITERATIONS` bzw. eine künftige
  Keep-Alive-Variante messbar.
