import json, time
import gibraltar as g
from node_server import load_priv, load_pub, make_record, owner_sign
now = int(time.time())
rec = make_record(load_pub("omega"), now - 60)
sig = owner_sign(load_priv("owner"), f"register|{g.digest(rec)}|{now}")
json.dump({"rec": rec, "ts": now, "sig": sig}, open("omega_reg.json", "w"))
print("wrote omega_reg.json; start the node within 120s")
