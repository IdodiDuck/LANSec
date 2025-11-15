import time
from collections import deque

class SlidingWindowCounter:
    def __init__(self, window_seconds=10, max_items=1000):
        self.window = window_seconds
        self.max_items = max_items
        self.table = {}  # key -> deque[timestamps]

    def record(self, key, now=None):
        now = now or time.time()
        dq = self.table.get(key)
        if dq is None:
            dq = deque()
            self.table[key] = dq

        dq.append(now)

        cutoff = now - self.window

        # prune
        while dq and dq[0] < cutoff:
            dq.popleft()

        # cap
        while len(dq) > self.max_items:
            dq.popleft()

        return len(dq)


class RateAlert:
    def __init__(self, threshold, alert_cooldown):
        self.threshold = threshold
        self.cooldown = alert_cooldown
        self.last_alert = {}

    def should_alert(self, key, count, now=None):
        now = now or time.time()

        if count < self.threshold:
            return False

        last = self.last_alert.get(key, 0)

        if now - last >= self.cooldown:
            self.last_alert[key] = now
            return True

        return False
