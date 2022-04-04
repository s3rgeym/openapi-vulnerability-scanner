import datetime
import random


def random_datetime(
    start: datetime.datetime = datetime.datetime(1900, 1, 1, 0, 0, 0),
    end: datetime.datetime = datetime.datetime.now(),
) -> datetime.datetime:
    return start + (end - start) * random.random()
