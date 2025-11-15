import time

class BaseDetector:
    INFO_INTERVAL = 1.0
    INFO_DELTA = 5

    def __init__(self, counter, alerter, name):
        self.counter = counter
        self.alerter = alerter
        self.name = name

        self.last_info_time = {}
        self.last_info_count = {}

    def count_event(self, key):
        now = time.time()

        count = self.counter.record(key, now)

        last_t = self.last_info_time.get(key, 0)
        last_c = self.last_info_count.get(key, 0)

        if (now - last_t >= self.INFO_INTERVAL) or (count - last_c >= self.INFO_DELTA):
            self.last_info_time[key] = now
            self.last_info_count[key] = count

        return count if self.alerter.should_alert(key, count, now) else None
