# SSIN-Cakake

Reference implementation and simulation harness for the paper:

> **Collaborator-assisted Handover and Authenticated Key Exchange Protocol with KCI-Resistant for Space-Sea Integrated Networks**

This repository contains the proof-of-concept Python implementation of the
proposed **SSINAuth** (a.k.a. *Cakake*) protocol together with the four baseline
schemes used for comparison, plus a Docker-based network simulator that
reproduces the experimental results reported in the paper.

> ⚠️ The cryptographic code is built on top of the
> [MIRACL Core](https://github.com/miracl/core) Python reference implementation
> and is intended for research and reproducibility only. **Do not use it in
> production** — it is not side-channel hardened and has not been independently
> audited.

---

## 1. Repository layout

```
ssin1018/
├── protocols/                 # Pure-Python protocol implementations
│   ├── ssinauth.py            # Proposed Cakake / SSINAuth protocol
│   ├── guo2021.py             # Baseline: Guo et al. 2021
│   ├── liu2022.py             # Baseline: Liu et al. 2022
│   ├── ren2023.py             # Baseline: Ren et al. 2023
│   ├── yang2024.py            # Baseline: Yang et al. 2024
│   ├── zhu2023.py             # Baseline: Zhu et al. 2023
│   ├── miracl_aes.py          # AES-CTR helper used by secure channels
│   ├── bn254/                 # MIRACL Core BN254 pairing-friendly curve
│   ├── bls12381/              # MIRACL Core BLS12-381 curve
│   ├── ed25519/               # MIRACL Core Ed25519 curve
│   ├── config.py              # Curve selector (from MIRACL Core)
│   └── run_ssinauth_demo.py   # End-to-end demo for SSINAuth
├── simulation/                # Containerised network experiments
│   ├── Dockerfile             # Image used by every entity in the topology
│   ├── docker-compose*.yml    # One compose file per protocol under test
│   ├── app/                   # Orchestrators, UE/relay/server roles, codecs
│   ├── configs/               # Network scenarios (LEO-only, rain fade, …)
│   ├── shared/                # Shared volume: offline contexts + caches
│   └── results/               # CSV / JSON output collected from runs
├── tests/                     # Pytest unit and benchmark tests
└── README.md
```

The `protocols/` package mirrors a subset of the MIRACL Core layout so that the
elliptic-curve primitives can be imported directly (`from bn254.ecp import …`).
The protocol modules add the higher-level message flow and key-derivation logic
described in the paper.

---

## 2. The proposed protocol (SSINAuth / Cakake)

`protocols/ssinauth.py` models the five phases of the protocol:

1. **System initialisation** — each domain runs a Key Generation Centre
   (`DomainKGC`) that publishes its master public point.
2. **Registration** — every entity (UE, helper `S_A`, authenticator `S_B`)
   obtains a partial private key from its KGC and combines it with a fresh
   secret to form the long-term key `SK_i`.
3. **Pre-authentication via the helper** — a four-message relay
   `UE → S_A → S_B → S_A → UE` exchanged over secure channels established with
   `establish_secure_channel(...)`.
4. **Public-channel mutual authentication** — the public uplink/downlink
   computes `Q_i = m_i · (h·P_pub + pk + P)` and verifies
   `SK_B · Q_i ?= M_i`. The shared point `m_i · M_B` is hashed with `H3`
   into the session key.
5. **Batch verification** — the authenticator uses a VRF-derived seed to pick a
   random subset (Level-1) and to weight an aggregate equation (Level-2),
   amortising the cost over many concurrent UEs.

A complete walk-through is available in `protocols/run_ssinauth_demo.py`:

```bash
cd protocols
python3 run_ssinauth_demo.py
```

It registers three UEs, runs a single-user authentication, and then exercises
the batch-verification path.

### Key design properties (per the paper)

* **KCI-resistance** — compromise of either party's long-term key is
  insufficient to derive past or future session keys, because the shared point
  also depends on ephemeral scalars `m_i, m_B` chosen per session.
* **Collaborator-assisted handover** — the helper `S_A` performs the heavy
  pre-authentication work so the target authenticator only has to validate a
  short uplink during the visibility window.
* **Batch verification with VRF sampling** — `batch_verify(...)` aggregates
  many uplinks into a single equation while still catching forged requests via
  a randomised audit subset.

---

## 3. Baseline protocols

The following peer schemes are re-implemented under `protocols/` for fair
comparison in the same simulation harness:

| Module          | Reference                                                                 |
| --------------- | ------------------------------------------------------------------------- |
| `guo2021.py`    | Guo et al., 2021 — SIN access and handover authentication                 |
| `liu2022.py`    | Liu et al., 2022 — Satellite-to-ground integrated network authentication  |
| `ren2023.py`    | Ren et al., 2023 — SIN authentication protocol                            |
| `yang2024.py`   | Yang et al., 2024 — Conditional privacy-preserving aggregate signature    |
| `zhu2023.py`    | Zhu et al., 2023 — Conditional privacy-preserving aggregate signature     |

Each module exposes the same set of primitives (registration, access
authentication, handover, aggregate / batch verification when applicable) so
that the orchestrator can drive them through identical scenarios.

---

## 4. Reproducing the experiments

The `simulation/` directory uses Docker Compose to spin up the entities
(UE, relay LEO, target LEO / RSU, GS / app server, …) on dedicated bridge
networks. Latency, jitter, packet loss and rain-fade Markov states are injected
into each container with `tc netem`.

### 4.1 Prerequisites

* Docker Engine ≥ 24 with `docker compose`
* `NET_ADMIN` capability for the simulation containers (already requested in
  every compose file)
* Python ≥ 3.11 on the host (only needed for the orchestrator and helper
  scripts)

### 4.2 Build the image and pre-compute offline contexts

```bash
cd simulation
docker compose build
python3 app/generate_offline_context.py            # SSINAuth context
python3 app/guo2021_generate_context.py            # Guo 2021 context
python3 app/liu2022_generate_context.py            # Liu 2022 context
python3 app/ren2023_generate_context.py            # Ren 2023 context
python3 app/yang2024_generate_context.py           # Yang 2024 context
python3 app/zhu2023_generate_context.py            # Zhu 2023 context
```

Each script writes a pickled offline context to `simulation/shared/` which is
mounted into every container at `/shared`.

### 4.3 Launch a topology and run a scenario

For the proposed protocol:

```bash
docker compose -f docker-compose.yml up -d
python3 app/orchestrator.py --config configs/s1_online_only.yaml
```

For a baseline (e.g. Guo 2021):

```bash
docker compose -f docker-compose-guo2021.yml up -d
python3 app/guo2021_orchestrator.py --config configs/g1_online_only.yaml
```

Switch the YAML to compare different network conditions:

| Suffix             | Scenario                                     |
| ------------------ | -------------------------------------------- |
| `*_online_only`    | Stable LEO link, baseline RTT/jitter/loss     |
| `*_rain_fade`      | Gilbert–Elliott rain-fade Markov channel      |
| `*_short_window`   | Short visibility window, frequent handover    |

Per-run measurements (RTT, success/failure, retransmissions, etc.) are written
into `simulation/results/final_<scenario>.csv`.

### 4.4 Tear down

```bash
docker compose -f docker-compose.yml down -v
```

---

## 5. Running the unit tests

```bash
pip install pytest pyyaml
pytest tests/
```

The `tests/` suite covers the baseline protocol implementations and includes a
`test_ren2023_benchmark.py` micro-benchmark used while tuning the orchestrator.

---

## 6. Citing this work

If you use this code, please cite the paper:

```bibtex
@article{ssin_cakake,
  title   = {Collaborator-assisted Handover and Authenticated Key Exchange
             Protocol with KCI-Resistant for Space-Sea Integrated Networks},
  author  = {Xuru Li and collaborators},
  journal = {(to appear)},
  year    = {2026}
}
```

---

## 7. License

* The MIRACL Core sources under `protocols/bn254/`, `protocols/bls12381/`,
  `protocols/ed25519/`, `protocols/constants.py` and `protocols/config.py` are
  redistributed under the **Apache License, Version 2.0** (see the headers of
  the individual files for the original copyright notice from MIRACL UK Ltd.).
* The protocol implementations, simulation harness, configuration files, and
  experimental scripts authored for this project are released under the
  **MIT License** unless stated otherwise in the file header.

---

## 8. Acknowledgements

* [MIRACL Core](https://github.com/miracl/core) for the elliptic-curve and
  pairing primitives that make the Python prototype tractable.
* The authors of Guo 2021, Liu 2022, Ren 2023, Yang 2024 and Zhu 2023 for
  publishing the schemes used as comparison baselines.
