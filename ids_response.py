import json
import subprocess
import threading
import time
from datetime import datetime

EVE = "/var/log/suricata/eve.json"
BLOCK_SIDS = {1000002, 1000003, 1000004}
WHITELIST = {"127.0.0.1", "::1", "192.168.100.1"}
BLOCK_SECONDS = 60
LOGFILE = "blocked_ips.log"
blocked = set()


def log(msg):
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    with open(LOGFILE, "a") as f:
        f.write(line + "\n")


def unblock(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
    blocked.discard(ip)
    log(f"UNBLOCKED {ip}")


def block(ip, sig):
    if ip in WHITELIST or ip in blocked or ":" in ip:
        return
    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)
    blocked.add(ip)
    log(f"BLOCKED {ip} for {BLOCK_SECONDS}s  reason: {sig}")
    threading.Timer(BLOCK_SECONDS, unblock, args=(ip,)).start()


def main():
    log("Response system started. Waiting for alerts (Ctrl+C to stop)...")
    with open(EVE, "r") as f:
        f.seek(0, 2)
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if event.get("event_type") != "alert":
                    continue
                alert = event["alert"]
                log(f"ALERT: {alert['signature']}  src={event['src_ip']} dst={event['dest_ip']}")
                if alert["signature_id"] in BLOCK_SIDS:
                    block(event["src_ip"], alert["signature"])
        except KeyboardInterrupt:
            print("\nStopping, removing blocks...")
            for ip in list(blocked):
                unblock(ip)


if __name__ == "__main__":
    main()
