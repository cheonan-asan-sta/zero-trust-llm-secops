"""Serialize cache lookup and construction, not just insertion after a miss."""

import threading
from functools import lru_cache, wraps


def single_cached_factory(factory):
    cached = lru_cache(maxsize=1)(factory)
    lock = threading.RLock()

    @wraps(factory)
    def get():
        # lru_cache permits duplicate concurrent misses. Include its lookup in
        # this lock so exactly one worker owns first construction in the process.
        with lock:
            return cached()

    def clear():
        with lock:
            cached.cache_clear()

    get.cache_clear = clear
    get.cache_info = cached.cache_info
    return get
