import time
from collections import deque

class SlidingWindowCounter:
    """
    Implements a Sliding Window algorithm for precise event tracking.
    Unlike a fixed window, this counts events in a rolling timeframe, 
    making it much harder for attackers to evade detection by timing their bursts.
    """
    def __init__(self, window_seconds=10, max_items=1000):
        self.window = window_seconds
        self.max_items = max_items
        self.table = {}  # Dictionary mapping keys (e.g., IPs) to a deque of timestamps

    def record(self, key, now=None):
        """
        Records an event occurrence and returns the current count within the window.
        """
        now = now or time.time()
        
        # Get or create a double-ended queue (deque) for this key
        dq = self.table.get(key)
        if dq is None:
            dq = deque()
            self.table[key] = dq

        # Add the current event timestamp
        dq.append(now)

        cutoff = now - self.window

        # Remove timestamps that have fallen out of the rolling window
        while dq and dq[0] < cutoff:
            dq.popleft()

        # Prevent memory exhaustion by limiting the total items stored per key
        while len(dq) > self.max_items:
            dq.popleft()

        return len(dq)


class RateAlert:
    """
    Determines if an event count warrants an alert based on thresholds
    and manages 'alert fatigue' using a cooldown period.
    """
    def __init__(self, threshold, alert_cooldown):
        self.threshold = threshold
        self.cooldown = alert_cooldown
        self.last_alert = {} # Tracks the last time an alert was issued per key

    def should_alert(self, key, count, now=None):
        """
        Logic to decide if an alert should be triggered.
        """
        now = now or time.time()

        # Threshold Check: Is the activity level actually suspicious?
        if count < self.threshold:
            return False

        # Cooldown Check: Have we already alerted on this recently?
        last = self.last_alert.get(key, 0)

        if now - last >= self.cooldown:
            # Threshold met and cooldown expired - trigger new alert
            self.last_alert[key] = now
            return True

        # Threshold met but still in cooldown period
        return False