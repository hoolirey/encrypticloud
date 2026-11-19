import sys, inspect, node_server as n
m = sys.modules[n.NodeAgent.__module__]
for k in ("scale", "place", "workload_create", "config_edit", "delete"):
    print(k, "->", inspect.getsource(m.ALLOWLIST[k]).strip())
for mod in (m, n):
    if hasattr(mod, "msign"):
        print(inspect.getsource(mod.msign)); break
