import inspect, node_server as n, gibraltar as g
for name in ("authorize", "compute_tier", "derive_flags", "canonical_json", "load_priv"):
    for mod in (n, g):
        if hasattr(mod, name):
            print(inspect.getsource(getattr(mod, name))); break
print("ALLOWLIST:", list(n.ALLOWLIST), "COOLOFF:", n.COOLOFF)
print(inspect.getsource(n.main))
