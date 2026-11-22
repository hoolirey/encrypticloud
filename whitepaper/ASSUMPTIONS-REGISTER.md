# ENCRYPTICLOUD Assumptions Register

Each row: what is assumed, the test that could kill it, and what dies with it.
**[G]** = gating (the design collapses wholesale if it fails). INV-4 binds interpretation, never evidential weight.

## Physical
| ID | Assumption | Falsification test | Blast radius |
|---|---|---|---|
| P1 [G] | Link latency ≈ d/c; propagation dominates jitter on face links | Jitter distribution per face type vs analytic floor, across hardware generations | §3.2 TWTT, §11R coherence ladder, §19.6 pricing unit |
| P2 [G] | ~1 µs coherence achievable in a 10 m boxel | Discipline + queuing jitter campaigns on T0-class hardware | §3.3 NUMA semantics, coherent-region claims, §8R API |
| P3 | Skew composes linearly across nesting levels w | Multi-level TWTT | §3R coherence identity, scale-ladder routing |
| P4 | T2 FSO loss ~14%, acceptable interleaving latency | Seasonal/aerosol/turbulence campaigns at 20–50 km | §5 erasure math, §11R T2 bands |
| P5 [G] | CMOS bound tables are tight enough to be useful, loose enough to avoid false disputes | Claimed-work vs measured-energy distributions over real hardware variance | §19.3/§19.4 tier-1 metering |
| P6 | Wind-drift forecasts accurate over mirror horizon W | Hindcast vs real stratospheric traces | §12.2/§7.3 |
| P7 | Per-cube thermal model good enough for adjudication-grade energy checks | Controlled-load thermal campaigns | §7.5, §19.3 |
| P8 | Altitude soft-error rates affordable within scrub budget | Radiation campaigns vs scrub bandwidth | §B1, T2 viability |

## Trust / cryptographic
| ID | Assumption | Falsification test | Blast radius |
|---|---|---|---|
| T1 [G] | TEE attestation honesty per vendor root | Continuous side-channel/forgery audit; multi-vendor diversity bounds blast radius | §19.1 meters, §6 residency |
| T2 [G] | Disjoint-witness d/c cross-checks resist collusion at realistic attacker budgets | Witness-selection red-teaming; how many disjoint witnesses must an attacker corrupt | §18.4 rule 2, §17.3.2 |
| T3 | Signature lifetimes outpace migration | Crypto-agility review vs migration clocks | §18 title keys, tree heads |
| T4 | Beacon unpredictability holds | Post-hoc statistics on commit-reveal outputs | §19.5 canaries, §20.7.5 coupling |
| T5 | Ledger replica diversity survives partitions and operator compromise | Partition/churn simulation (sim/ covers the fork path) | §18.7.5 |
| T6 | Decoder-kernel supply chain holds | Reproducible builds, provenance audit | All historical verification |
| T7 | Governance cannot retro-interpret (INV-4 enforceable) | Quorum-capture modeling | §18–§20 guarantees |

## Incentive / economic
| ID | Assumption | Falsification test | Blast radius |
|---|---|---|---|
| E1 | Rent-fraction pool funds monitors, canaries, juries at realistic volume | Cost model vs claim volume; pool shrinks when fabric is quiet | §18 monitors, §19.5, jury tier |
| E2 | De-minimis band edge unexploitable | Adversarial splitting simulation (sim/ covers it) | §19.7.1 |
| E3 | Canary statistics detect chronic under-commit despite evasion | Evader-vs-canary simulation (sim/ covers it) | D3, under-delivery detection |
| E4 | Coherence-second pricing tracks usefulness across w-levels | Pricing experiments | §19.6 |

## Scheduling / AI
| ID | Assumption | Falsification test | Blast radius |
|---|---|---|---|
| S1 | Mirror residuals converge faster than divergence cascades | §16.2 stress simulation | §13, §14 |
| S2 | Claim forecasts stay bounded-error on real traces | Trace-driven backtests | §14.1 |
| S3 | Pressure-poisoning detectable within tolerance | Poisoning red-team | §7.1, all cross-region routing until E3 lands |
| S4 | Whitelisted AI action set is complete and sufficient | Formal enumeration review | INV-3 claim |

## Federation / legal
| ID | Assumption | Falsification test | Blast radius |
|---|---|---|---|
| F1 | Substrate consent obtainable where fabric utility exists | Pilots, normative analysis | T0 economics |
| F2 | Jurisdiction re-binding under drift resolvable inside consent framework | Legal-mechanism prototype on C2 drift case | D1 |
| F3 | Inter-root alignment achieves rendezvous across independent regions | Federation prototype between two independent roots | §11R.5.2, border routing |

## Open classification
E3 (cross-title pressure-field trust) is load-bearing: packet forwarding consumes untrusted published metrics until it lands.

## Simulator findings (sim/fabric_sim.py, seed 1)
- P5: a ceiling slack of ~0.10 gives ~0.07% honest false flags but catches only ~86% of overbilling; 0.20 catches ~57%. Energy cannot see underreporting at all.
- E3: if a title can identify canaries 95% of the time, flagging a 70%-delivery title takes ~500 epochs vs ~3 at 0%. Canary indistinguishability is the whole game.
- E2: per-claim de-minimis bands leak ~99% of sliced skim; epoch aggregation flags every epoch.
- §20.3: a stalled region spanning the lattice halts the wave; dual-debt alone does not cross it.
- §18.4.4: tenure weighting cuts Sybil quorum capture from ~97% to ~7% in the modeled setup.
- T2: 7-of-9 disjoint witnesses accept a false claim ~9% of the time at 50% corruption; the claim depends on witnesses being genuinely disjoint from the attacker.
