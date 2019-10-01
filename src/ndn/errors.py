class NetworkError(Exception):
    pass


class InterestTimeout(Exception):
    pass


class InterestNack(Exception):
    reason: int

    def __init__(self, reason: int):
        self.reason = reason
