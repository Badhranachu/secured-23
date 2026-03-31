import time


def timer_start():
    return time.perf_counter()


def elapsed_ms(started_at):
    return round((time.perf_counter() - started_at) * 1000, 2)


def build_metrics(**values):
    return {key: value for key, value in values.items() if value is not None}
