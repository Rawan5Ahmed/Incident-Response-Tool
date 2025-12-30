import re
import json
from datetime import datetime

# Attempt JSON parse, fall back to regex
_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_LEVEL_RE = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL)\b")


def _normalize_ts(val):
    if not val:
        return None
    # Accept ISO-like and 'YYYY-MM-DD HH:MM:SS'
    try:
        # try ISO
        dt = datetime.fromisoformat(val.replace('Z', '+00:00'))
        return dt.isoformat()
    except Exception:
        pass
    try:
        # try common format
        dt = datetime.strptime(val, '%Y-%m-%d %H:%M:%S')
        return dt.isoformat()
    except Exception:
        return val


def _normalize_level(level):
    if not level:
        return None
    l = level.upper()
    if l == 'WARN':
        return 'WARNING'
    return l


def parse_log_line(line: str):
    line = line.strip()
    parsed = {'raw': line, 'ts': None, 'level': None, 'message': None}
    # JSON
    try:
        obj = json.loads(line)
        # heuristics
        parsed['ts'] = _normalize_ts(obj.get('timestamp') or obj.get('time') or obj.get('ts'))
        parsed['level'] = _normalize_level(obj.get('level') or obj.get('severity'))
        parsed['message'] = obj.get('message') or obj.get('msg') or json.dumps(obj)
        return parsed
    except Exception:
        pass
    # Timestamp
    m = _TS_RE.search(line)
    if m:
        parsed['ts'] = _normalize_ts(m.group(1))
    lm = _LEVEL_RE.search(line)
    if lm:
        parsed['level'] = _normalize_level(lm.group(1))
    # message fallback strip ts and level
    msg = line
    if parsed['ts']:
        msg = msg.replace(parsed['ts'], '')
    if parsed['level']:
        msg = msg.replace(parsed['level'], '')
    parsed['message'] = msg.strip()
    return parsed
