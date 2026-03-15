import time

class BaseDetector:
    """
    Base class for all frequency-based detection modules.
    It provides a standardized interface for counting events and triggering alerts
    while implementing 'throttling' to manage update frequency.
    """
    
    # Configuration for internal logging/update frequency
    INFO_INTERVAL = 1.0  # Minimum time (seconds) between info updates
    INFO_DELTA = 5 # Minimum count increase to trigger an info update

    def __init__(self, counter, alerter, name):
        """
        :param counter: A sliding window or rate-limiting counter object.
        :param alerter: A RateAlert object that defines the threshold logic.
        :param name: The display name of the detector (e.g., "SYN Flood").
        """
        self.counter = counter
        self.alerter = alerter
        self.name = name

        # Tracks the last update state per source key (e.g., IP address)
        self.last_info_time = {}
        self.last_info_count = {}

    def count_event(self, key):
        """
        Records a new event and checks if it warrants an alert.
        
        :param key: The unique identifier for the event source.
        :return: The current event count if an alert should be triggered, otherwise None.
        """
        now = time.time()

        # Record the event in the sliding window
        count = self.counter.record(key, now)

        # Throttling Logic:
        # Determine if enough time or enough events have passed since the last update.
        last_t = self.last_info_time.get(key, 0)
        last_c = self.last_info_count.get(key, 0)

        if (now - last_t >= self.INFO_INTERVAL) or (count - last_c >= self.INFO_DELTA):
            # Update the tracking state for this source
            self.last_info_time[key] = now
            self.last_info_count[key] = count

        # Alert Evaluation:
        # Delegate the decision to the alerter component
        if self.alerter.should_alert(key, count, now):
            return count
        
        return None