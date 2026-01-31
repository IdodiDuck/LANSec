import time
from scapy.all import ICMP, IP, send

# Input Helpers - 
def get_user_input(prompt, default, input_type=int):
    raw = input(f"{prompt} (default {default}): ").strip()
    try:
        return input_type(raw) if raw else default
    except ValueError:
        return default

# Mechanics - 
class TrafficEngine:
    def __init__(self, target_ip):
        self.target_ip = target_ip

    def dispatch(self, pps, protocol="ICMP"):
        pkts = [IP(dst=self.target_ip)/ICMP() for _ in range(pps)]
        send(pkts, verbose=False)

# Desired Supervised Scenarios - 
class AnomalyScenarios:
    def __init__(self, engine):
        self.engine = engine

    def burst(self):
        pps = get_user_input("Packets Per Second", 1000)
        sec = get_user_input("Duration (sec)", 5)
        
        print(f"\nInjecting Burst: {pps} PPS")
        for _ in range(sec):
            self.engine.dispatch(pps)
            time.sleep(1)

    def drift(self):
        s_pps = get_user_input("Start PPS", 10)
        e_pps = get_user_input("End PPS", 500)
        sec   = get_user_input("Total Duration", 30)
        
        print(f"\n[!] Injecting DRIFT: {s_pps} -> {e_pps} PPS")
        steps = 5

        for i in range(steps):
            current_pps = int(s_pps + (e_pps - s_pps) * (i / (steps - 1)))
            print(f"    Step {i+1}: {current_pps} PPS")
            for _ in range(max(1, sec // steps)):
                self.engine.dispatch(current_pps)
                time.sleep(1)

def main():
    target = input("Target IP (default 127.0.0.1): ").strip() or "127.0.0.1"
    scenarios = AnomalyScenarios(TrafficEngine(target))

    menu = {
        "1": ("Sudden Burst", scenarios.burst),
        "2": ("Gradual Drift", scenarios.drift)
    }

    print("\nSelect Scenario:")
    for key, (name, _) in menu.items():
        print(f"[{key}] {name}")

    choice = input("\nChoice: ").strip()
    
    if choice in menu:
        menu[choice][1]()
        print("\nDone execution.")

    else:
        print("\nnvalid Choice.")

if __name__ == "__main__":
    main()