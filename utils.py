import os
import threading
import logging
from concurrent.futures import ThreadPoolExecutor
import gc

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MemoryOptimizer:
    CHUNK_SIZE = 1024 * 1024
    MAX_WORKERS = 4

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=self.MAX_WORKERS)
        self._stopped = False
        self._thread_lock = threading.Lock()

    def stop(self):
        with self._thread_lock:
            self._stopped = True
            if self.executor:
                self.executor.shutdown(wait=False)

    def __del__(self):
        self.stop()

__all__ = ['MemoryOptimizer']
