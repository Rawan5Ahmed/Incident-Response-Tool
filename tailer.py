import threading
import time
from parsers import parse_log_line

class Tailer:
    def __init__(self, db):
        self.db = db
        self._thread = None
        self._stop = threading.Event()

    def _tail_loop(self, path):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                # seek to end
                fh.seek(0, 2)
                while not self._stop.is_set():
                    line = fh.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    parsed = parse_log_line(line)
                    self.db.insert_log(parsed)
        except Exception as e:
            print('Tailer error:', e)

    def start(self, path):
        if self._thread and self._thread.is_alive():
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._tail_loop, args=(path,), daemon=True)
        self._thread.start()
        return True

    def stop(self):
        if self._thread and self._thread.is_alive():
            self._stop.set()
            self._thread.join(timeout=2)
            return True
        return False
