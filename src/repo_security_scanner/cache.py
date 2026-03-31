from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path


class FileCache:
    def __init__(self, cache_dir: str = None):
        if cache_dir is None:
            cache_dir = os.path.join(Path.home(), ".cache", "repo-security-scanner")
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _key_path(self, key: str) -> Path:
        safe_key = hashlib.sha256(key.encode()).hexdigest()[:32]
        return self.cache_dir / f"{safe_key}.json"

    def get(self, key: str, max_age_seconds: int) -> dict | list | None:
        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if time.time() - data.get("_ts", 0) > max_age_seconds:
                return None
            return data.get("payload")
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, key: str, payload) -> None:
        path = self._key_path(key)
        try:
            data = {"_ts": time.time(), "payload": payload}
            path.write_text(json.dumps(data))
        except OSError:
            pass

    def clear(self) -> None:
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
            except OSError:
                pass
