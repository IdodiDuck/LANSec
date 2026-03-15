import time
from scapy.all import ICMP, IP, send

# Input Helpers - 
def get_user_input(prompt, default, input_type=int):
    """
    Safely retrieves user input with a default fallback and type casting.

    :param prompt: The description to show the user.
    :param default: The value to use if input is empty.
    :param input_type: The expected data type (default: int).
    :return: The user's value or the default value.
    """
    raw = input(f"{prompt} (default {default}): ").strip()
    try:
        return input_type(raw) if raw else default
    except ValueError:
        return default

# Mechanics - 
class TrafficEngine:
    """
    Core engine responsible for constructing and dispatching network packets.
    """
    def __init__(self, target_ip):
        """
        :param target_ip: The IP address of the victim/target machine.
        """
        self.target_ip = target_ip

    def dispatch(self, pps):
        """
        Generates and sends a batch of packets to simulate network load.

        :param pps: Packets Per Second to send.
        """
        pkts = [IP(dst=self.target_ip)/ICMP() for _ in range(pps)]
        send(pkts, verbose=False)

# Desired Supervised Scenarios - 
class AnomalyScenarios:
    """
    Pre-defined attack scenarios to validate IDS detection capabilities.
    """
    def __init__(self, engine):
        """
        :param engine: An instance of TrafficEngine.
        """
        self.engine = engine

    def burst(self):
        """
        Scenario 1: Sudden Burst.
        Simulates a high-volume spike in traffic, testing Fixed Threshold detectors.
        """
        pps = get_user_input("Packets Per Second", 1000)
        sec = get_user_input("Duration (sec)", 5)
        
        print(f"\nInjecting Burst: {pps} PPS")
        for _ in range(sec):
            self.engine.dispatch(pps)
            time.sleep(1)

    def drift(self):
        """
        Scenario 2: Gradual Drift.
        Increases traffic intensity over time to test Anomaly Detection and Dynamic Baselines.
        """
        s_pps = get_user_input("Start PPS", 10)
        e_pps = get_user_input("End PPS", 500)
        sec   = get_user_input("Total Duration", 30)
        
        print(f"\n[!] Injecting DRIFT: {s_pps} -> {e_pps} PPS over {sec} seconds")
        steps = 5

        for i in range(steps):
            # Calculate linear increase for the current step
            current_pps = int(s_pps + (e_pps - s_pps) * (i / (steps - 1)))
            print(f"    -> Current intensity: {current_pps} PPS")
            
            for _ in range(max(1, sec // steps)):
                self.engine.dispatch(current_pps)
                time.sleep(1)

def main():
    """
    Interactive CLI for choosing and executing traffic injection scenarios.
    """
    print("IDPS Test Suite: Traffic Generator")
    target = input("Target IP (default 127.0.0.1): ").strip() or "127.0.0.1"
    scenarios = AnomalyScenarios(TrafficEngine(target))

    menu = {
        "1": ("Sudden Burst (Test Static Thresholds)", scenarios.burst),
        "2": ("Gradual Drift (Test Dynamic Baselines)", scenarios.drift)
    }

    print("\nSelect Injection Scenario:")
    for key, (name, _) in menu.items():
        print(f"[{key}] {name}")

    choice = input("\nChoice: ").strip()
    
    if choice in menu:
        try:
            menu[choice][1]()
            print("\nExecution completed successfully.")

        except KeyboardInterrupt:
            print("\n[!] Injection stopped by user.")

    else:
        print("\n[X] Invalid Choice.")

if __name__ == "__main__":
    main()