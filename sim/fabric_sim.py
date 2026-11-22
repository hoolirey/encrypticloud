#!/usr/bin/env python3
"""ENCRYPTICLOUD fabric simulator: §18 ledger/forks, §19 metering, §20 wavefront.
Stdlib only, deterministic per --seed. Signatures are HMAC stand-ins (sim only)."""
import argparse, hashlib, hmac, random, sys
from dataclasses import dataclass

def h(*p):
    m = hashlib.sha3_384()
    for x in p: m.update(str(x).encode() + b"|")
    return m.hexdigest()

class Keys:
    def __init__(s, rng): s.sec, s.rng = {}, rng
    def new(s, n): s.sec[n] = h("key", n, s.rng.random()); return n
    def sign(s, n, msg): return hmac.new(s.sec[n].encode(), msg.encode(), hashlib.sha3_384).hexdigest()
    def ok(s, n, msg, sig): return n in s.sec and hmac.compare_digest(s.sign(n, msg), sig)

@dataclass
class E:
    action: str; epoch: int; signer: str; new_key: str; parent: str
    consent: bool = True; audit: bool = True; sig: str = ""
    def body(s): return h(s.action, s.epoch, s.signer, s.new_key, s.parent, s.consent, s.audit)
    def ref(s): return h(s.body(), s.sig)

def mk(keys, act, ep, signer, new_key, parent, forge_with=None, **kw):
    e = E(act, ep, signer, new_key, parent, **kw)
    e.sig = keys.sign(forge_with or signer, e.body()); return e

def build(keys, root, holders, n, start=0, prefix=None, gap_at=None, forge_at=None, bad_consent_at=None):
    """One entry per epoch. GENESIS, then ALIGN-APPOINT renewals; TRANSFER every 3rd epoch."""
    ch = list(prefix) if prefix else []
    hi = 0
    for i in range(len(ch), n):
        ep = start + i + (3 if gap_at == i else 0)
        if not ch:
            e = mk(keys, "GENESIS", ep, root, holders[0], "")
        else:
            prev = ch[-1]; act, nk = "ALIGN-APPOINT", prev.new_key
            if i % 3 == 0 and hi + 1 < len(holders): hi += 1; act, nk = "TRANSFER", holders[hi]
            e = mk(keys, act, ep, prev.new_key, nk, prev.ref(),
                   forge_with=("attacker" if forge_at == i else None),
                   consent=(bad_consent_at != i), audit=(gap_at != i))
        ch.append(e)
    return ch

def wellformed(keys, root, ch):
    if not ch or ch[0].action != "GENESIS" or ch[0].signer != root or ch[0].parent: return False
    if not keys.ok(root, ch[0].body(), ch[0].sig): return False
    for a, e in zip(ch, ch[1:]):
        if e.parent != a.ref() or e.signer != a.new_key or not keys.ok(e.signer, e.body(), e.sig): return False
        if e.action in ("TRANSFER", "SUBDIVIDE") and not e.consent: return False
    return True

def physics_ok(ch): return all(e.audit for e in ch) and all(b.epoch - a.epoch <= 1 for a, b in zip(ch, ch[1:]))

def resolve(keys, root, chains):
    s = [i for i, c in enumerate(chains) if wellformed(keys, root, c)]
    if not s: return None, "no-valid-chain"
    if len(s) == 1: return s[0], "rule1"
    s2 = [i for i in s if physics_ok(chains[i])] or s
    if len(s2) == 1 and len(s2) < len(s): return s2[0], "rule2"
    top = max(len(chains[i]) for i in s2); s3 = [i for i in s2 if len(chains[i]) == top]
    if len(s3) == 1: return s3[0], "rule3"
    return None, "quorum"

def quorum_capture(rng, honest, att, ten_h, ten_a, k=9, weighted=True, trials=4000):
    pool = [("h", ten_h)] * honest + [("a", ten_a)] * att; won = 0
    for _ in range(trials):
        j = rng.sample(pool, k)
        w = lambda side: sum((t if weighted else 1) for s, t in j if s == side)
        won += w("a") > w("h")
    return won / trials

def wavefront(W=8, Hh=8, stalled=(), cap=6, max_ep=60):
    st = {(x, y): "old" for x in range(W) for y in range(Hh)}
    nb = lambda p: [q for q in ((p[0]+1,p[1]),(p[0]-1,p[1]),(p[0],p[1]+1),(p[0],p[1]-1)) if q in st]
    debt, charged, inv_ok = {}, 0, True
    for ep in range(max_ep):
        snap, ch = dict(st), False
        for p, s in snap.items():
            if p in stalled: continue
            if s == "old" and ((p == (0, 0) and ep == 0) or any(snap[q] != "old" for q in nb(p))): st[p] = "dual"; ch = True
            elif s == "dual" and all(snap[q] != "old" for q in nb(p)): st[p] = "new"; ch = True
        for p in st:
            if st[p] == "dual" and any(q in stalled for q in nb(p)) and debt.get(p, 0) < cap:
                debt[p] = debt.get(p, 0) + 1; charged += debt[p] == cap
        if any(st[p] == "new" and any(st[q] == "old" for q in nb(p)) for p in st): inv_ok = False
        live = [p for p in st if st[p] != "old"]; seen, stack = set(live[:1]), live[:1]
        while stack:
            for q in nb(stack.pop()):
                if st[q] != "old" and q not in seen: seen.add(q); stack.append(q)
        inv_ok &= len(seen) == len(live)
        if not ch and ep > 0: break
    n = lambda v: sum(s == v for s in st.values())
    return dict(epochs=ep, new=n("new"), dual=n("dual"), old=n("old"), invariant_ok=inv_ok, stall_charges=charged)

def p5_window(rng, slack, n=20000, sigma=0.03):
    """Energy-ceiling check: lender claim flagged if claimed > true*(1+slack+noise). Energy bounds overbilling only."""
    fp = sum(rng.gauss(0, sigma) < -slack for _ in range(n)) / n          # honest lender wrongly flagged
    caught = sum(rng.uniform(0.05, 0.4) > slack + rng.gauss(0, sigma) for _ in range(n)) / n  # overbill 5-40%
    return fp, caught

def ladder(rng, n=5000, cheat=0.2, tol=0.02, jury_acc=0.9, slack=0.1, sigma=0.03):
    pool = cheat_caught = cheats = honest_pen = skim_undet = 0
    for _ in range(n):
        true = rng.uniform(50, 150); a = true * (1 + rng.gauss(0, 0.003)); b = true * (1 + rng.gauss(0, 0.003)); who = None
        if rng.random() < cheat:
            d = rng.uniform(0.01, 0.4); cheats += 1
            if rng.random() < .5: a, who = true * (1 + d), "lender"      # overbill
            else: b, who = true * (1 - d), "borrower"                    # underreport (energy cannot see it)
        if abs(a - b) / ((a + b) / 2) <= tol:
            skim_undet += who is not None; continue                       # tier 1: reconcile at mean
        # hold -> forensic: physics first, then flat-fee jury
        lender_flag = a > true * (1 + slack + rng.gauss(0, sigma))
        if lender_flag: blame = "lender"
        else: blame = who if rng.random() < jury_acc and who else rng.choice(["lender", "borrower"])
        pen = 0.5 * abs(a - b); pool += pen
        if who and blame == who: cheat_caught += 1
        elif blame != who: honest_pen += 1
        elif not who: honest_pen += 1
    return dict(cheats=cheats, caught=cheat_caught / max(cheats, 1), undetected_in_tol=skim_undet / max(cheats, 1),
                honest_penalised=honest_pen, pool=round(pool))

def deminimis(rng, n=1000, band=1.0, epoch_len=50):
    skim = 0.99 * band * n                                                # slice every claim just under the band
    agg_flag = sum(0.99 * band * epoch_len > band * epoch_len ** 0.5 for _ in range(n // epoch_len))
    return dict(per_claim_undetected=round(skim, 1), epochs_flagged_with_aggregation=f"{agg_flag}/{n // epoch_len}")

def canary(rng, a, q, trials=300, window=50, thresh=4):
    """Title promised full reserve, delivers fraction a. q = prob it can tell a canary from real work."""
    t_all = []
    for _ in range(trials):
        hist, t = [], 0
        while t < 5000:
            t += 1
            for _ in range(5):                                            # canaries per epoch
                ok = rng.random() < q or rng.random() < a or rng.random() < 0.01 and a == 1
                hist.append(not ok)
            if sum(hist[-window:]) >= thresh: break
        t_all.append(t)
    return sum(t_all) / len(t_all)

def witnesses(rng, f, m=9, q=7, trials=40000):
    return sum(sum(rng.random() < f for _ in range(m)) >= q for _ in range(trials)) / trials

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--seed", type=int, default=1); ap.add_argument("--e3", action="store_true"); a = ap.parse_args()
    rng = random.Random(a.seed); keys = Keys(rng); root = keys.new("root"); keys.new("attacker")
    hs = [keys.new(f"H{i}") for i in range(6)]; fails = []
    def check(name, cond): print(f"  [{'PASS' if cond else 'FAIL'}] {name}"); cond or fails.append(name)

    print("§18 fork resolution (rules 1-4)")
    good = build(keys, root, hs, 9)
    w, r = resolve(keys, root, [good, build(keys, root, hs, 9, forge_at=5)]); check(f"forged signature -> rule1 winner=0 ({r})", (w, r) == (0, "rule1"))
    w, r = resolve(keys, root, [good, build(keys, root, hs, 9, bad_consent_at=3)]); check(f"missing consent-ref -> rule1 ({r})", (w, r) == (0, "rule1"))
    w, r = resolve(keys, root, [good, build(keys, root, hs, 9, gap_at=4)]); check(f"audit gap -> rule2 ({r})", (w, r) == (0, "rule2"))
    w, r = resolve(keys, root, [build(keys, root, hs, 6), good]); check(f"longer audited chain -> rule3 ({r})", (w, r) == (1, "rule3"))
    alt = build(keys, root, hs[::-1], 9)
    w, r = resolve(keys, root, [good, alt]); check(f"collusive equal split -> quorum ({r})", (w, r) == (None, "quorum"))
    print("§18.7.5 partition: both sides write, heal, detect")
    pre = build(keys, root, hs, 4); A = build(keys, root, hs, 7, prefix=pre); B = build(keys, root, hs[:1] + hs[2:], 7, prefix=pre)
    heads = {A[-1].ref(), B[-1].ref()}; w, r = resolve(keys, root, [A, B])
    check(f"divergent heads visible at heal ({len(heads)} heads); both sides stayed available", len(heads) == 2)
    check(f"same-length split from a common prefix escalates ({r}); title provisional until resolved", r in ("quorum", "rule3"))
    C = build(keys, root, hs, 9, prefix=pre); w, r = resolve(keys, root, [A, C])
    print(f"  NOTE: longer-lived partition side wins by rule3 ({r}); this biases toward the side that kept writing longest")
    print("§18.4.4 quorum capture, 9 jurors: attacker=60 titles tenure 1, honest=20 titles tenure 30")
    cw, cc = quorum_capture(rng, 20, 60, 30, 1, weighted=True), quorum_capture(rng, 20, 60, 30, 1, weighted=False)
    print(f"  capture rate tenure-weighted={cw:.3f}  count-weighted={cc:.3f}"); check("tenure weighting blunts title-count Sybil", cw < cc)

    print("§20.3 wavefront rollout (8x8)")
    for name, st in [("no stall", ()), ("single stalled interior node", ((4, 4),)), ("stalled wall x=4", tuple((4, y) for y in range(8)))]:
        r = wavefront(stalled=st); print(f"  {name}: {r}")
        check(f"{name}: wavefront invariant held", r["invariant_ok"])
    print("  FINDING: a stalled wall spanning the lattice halts the wave; neighbour dual-debt alone cannot cross it. Needs the deputized rule / bypass.")

    print("§19.3 P5 window: ceiling slack vs false flags vs overbill catch")
    for s in (0.0, 0.05, 0.1, 0.2, 0.4):
        fp, cc = p5_window(rng, s); print(f"  slack={s:.2f}  honest false-flag={fp:.4f}  overbill caught={cc:.3f}")
    print("§19.4 ladder (energy sees overbilling only; underreporting rests on the jury)")
    for jacc in (0.6, 0.9, 0.99):
        print(f"  jury_acc={jacc}: {ladder(rng, jury_acc=jacc)}")
    d = deminimis(rng); print(f"§19.7.1 de-minimis slicing: {d}"); check("aggregation exposes slicing", d["epochs_flagged_with_aggregation"].startswith("20/"))
    print("§19.5 canaries: mean epochs to flag a title delivering 70% of promised reserve")
    for q in (0.0, 0.5, 0.8, 0.95): print(f"  canary-identification q={q}: {canary(rng, 0.7, q):.1f} epochs")
    print("§18 patch-1 witness collusion: P(false alignment accepted), 7-of-9 disjoint witnesses")
    for f in (0.1, 0.3, 0.5, 0.7): print(f"  corrupted fraction of eligible witnesses={f}: {witnesses(rng, f):.4f}")
    if a.e3:
        print()
        run_e3(rng)

    print("\nRESULT:", "ALL CHECKS PASSED" if not fails else f"FAILED: {fails}"); sys.exit(bool(fails))

# ---- §21: cross-title pressure-field trust (added) ----

def pressure_divergence(rng, true_load, overload, reaction, n_epochs=200, tol=0.1, trials=400):
    """Sustained attack: region keeps publishing 'true_load' (falsely low) to attract traffic,
    but its REAL load (what neighbors actually experience routing through it) sits at
    true_load+overload the whole time, because it accepted traffic it lied its way into.
    observed = EMA of what neighbors actually measure, starting from the prior honest baseline.
    reaction = EMA smoothing (higher = adapts to the real overload faster -> shorter exploit
    window, but also reacts more to ordinary noise -> more false flags on honest regions).
    Returns: mean epochs of undetected real overload (exploit window), and false-flag rate
    on a region with the same reaction speed experiencing only ordinary load noise, no lie."""
    exploit_windows = []
    for _ in range(trials):
        observed = true_load                     # neighbors' prior, pre-attack baseline
        for ep in range(n_epochs):
            actual = true_load + overload + rng.gauss(0, 0.02)   # real sustained overload
            observed = reaction * actual + (1 - reaction) * observed
            published = true_load + rng.gauss(0, 0.01)           # the lie never updates
            if abs(published - observed) > tol:
                exploit_windows.append(ep); break
        else:
            exploit_windows.append(n_epochs)
    mean_window = sum(exploit_windows) / len(exploit_windows)

    false_flags = 0
    for _ in range(trials):
        observed = true_load
        flagged = False
        for ep in range(n_epochs):
            actual = true_load + rng.gauss(0, 0.08)              # ordinary noise, no lie at all
            observed = reaction * actual + (1 - reaction) * observed
            published = true_load + rng.gauss(0, 0.01)
            if abs(published - observed) > tol:
                flagged = True; break
        false_flags += flagged
    return dict(mean_exploit_window_epochs=round(mean_window, 2), honest_false_flag_rate=round(false_flags / trials, 4))


def disjoint_witness_topology(rng, degree, need=3, trials=20000):
    """A region has `degree` neighbors; a fraction `colluding` of ALL regions are attacker-controlled
    and mutually adjacent/same-appointment-tree (so they count as ONE witness for disjointness).
    Returns P(region can ever assemble `need` disjoint honest witnesses) under random neighbor assignment,
    swept over colluding fraction, for a fixed node degree."""
    out = {}
    for colluding in (0.0, 0.1, 0.2, 0.3, 0.4):
        ok = 0
        for _ in range(trials):
            neighbors = ["colluder" if rng.random() < colluding else f"n{rng.random()}" for _ in range(degree)]
            disjoint_honest = len(set(x for x in neighbors if x != "colluder"))
            ok += disjoint_honest >= need
        out[colluding] = round(ok / trials, 4)
    return out


def run_e3(rng):
    print("§21.5.1 pressure divergence: exploit window vs false-flag rate, by EMA reaction speed")
    for reaction in (0.02, 0.05, 0.1, 0.2, 0.4):
        r = pressure_divergence(rng, true_load=0.5, overload=0.3, reaction=reaction)
        print(f"  reaction={reaction:.2f}  {r}")
    print("  FINDING: faster reaction shortens the exploit window but raises honest false-flags during real spikes — same tradeoff shape as §19.3 P5.")

    print("§21.5.3 sparse-region disjoint-witness feasibility, need=3 disjoint honest reporters")
    for degree in (3, 5, 9):
        r = disjoint_witness_topology(rng, degree)
        print(f"  neighbor-degree={degree}: {r}")
    print("  FINDING: at degree=3 (lattice edge), even light collusion (10-20%) makes hitting 3 disjoint witnesses unreliable; interior nodes (degree=9) stay robust well past 30% collusion.")


if __name__ == "__main__": main()
