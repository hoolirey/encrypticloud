import sys, inspect, node_server as n
m = sys.modules[n.NodeAgent.__module__]
print("NodeAgent defined in:", m.__name__)
for k in ("REQUIRED", "BASE_TIER", "RED_FLAGS", "AMBER_FLAGS",
          "SNAPSHOT_REQUIRED", "COOLOFF"):
    print(k, "=", getattr(m, k, "NOT FOUND"))
al = getattr(m, "ALLOWLIST", None)
print("ALLOWLIST keys:", list(al) if al else "NOT FOUND")
if al and "read" in al:
    print(inspect.getsource(al["read"]))
print(inspect.getsource(n.main))
