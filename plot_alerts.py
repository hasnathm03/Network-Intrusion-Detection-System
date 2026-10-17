import json
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

EVE = "/var/log/suricata/eve.json"
sigs, srcs, times = Counter(), Counter(), Counter()

with open(EVE) as f:
    for line in f:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event_type") == "alert":
            sigs[e["alert"]["signature"][:45]] += 1
            srcs[e["src_ip"]] += 1
            times[e["timestamp"][11:16]] += 1

if not sigs:
    raise SystemExit("No alerts found yet. Run some attack tests first.")

fig, ax = plt.subplots(3, 1, figsize=(10, 12))
ax[0].barh(list(sigs.keys()), list(sigs.values()), color="tomato")
ax[0].set_title("Alerts by Type")
top = srcs.most_common(8)
ax[1].bar([t[0] for t in top], [t[1] for t in top], color="steelblue")
ax[1].set_title("Top Attacker IPs")
ax[1].tick_params(axis="x", rotation=30)
t = sorted(times.items())
ax[2].plot([x[0] for x in t], [x[1] for x in t], marker="o", color="seagreen")
ax[2].set_title("Alerts Over Time (per minute)")
plt.tight_layout()
plt.savefig("alerts_dashboard.png", dpi=120)
print(f"Saved alerts_dashboard.png  ({sum(sigs.values())} alerts total)")
