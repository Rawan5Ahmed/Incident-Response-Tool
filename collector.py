import platform
import subprocess
import os
import time
from parsers import parse_log_line
from logdb import LogDB
from model import Analyzer


def _run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 1, '', str(e)


def collect_windows(db, max_events=1000):
    # Use PowerShell to get events as JSON lines
    collected = 0
    for logname in ('System', 'Application'):
        # PowerShell command to get events and convert to JSON
        ps_cmd = (
            f"powershell -Command \"Get-WinEvent -LogName {logname} -MaxEvents {max_events} -ErrorAction SilentlyContinue "
            "| Select-Object TimeCreated, Id, LevelDisplayName, Message "
            "| ConvertTo-Json -Compress\""
        )
        rc, out, err = _run_cmd(ps_cmd)
        
        if rc == 0 and out:
            # Output might be a single JSON object or a list of objects
            # ConvertTo-Json can return a list [...] or a single {...}
            import json
            try:
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                
                for entry in data:
                    # Parse the JSON entry from PowerShell
                    ts = entry.get('TimeCreated')
                    # Handle ugly .NET date format /Date(123456789)/ if needed, 
                    # but typically ConverToJson produces readable strings or we can parse it.
                    # Actually ConvertTo-Json often gives /Date(ms)/ format.
                    # Let's clean it.
                    if isinstance(ts, str) and '/Date(' in ts:
                         ts = None # Let parser timestamp detection fallback or handle it later
                    
                    level = entry.get('LevelDisplayName')
                    msg = entry.get('Message') 
                    # Combine ID into message for context
                    full_msg = f"EventID: {entry.get('Id')} - {msg}"
                    
                    parsed = {
                        'raw': str(entry),
                        'ts': ts, # parse_log_line might not catch this specific format, but better than nothing
                        'level': level.upper() if level else 'INFO', 
                        'message': full_msg
                    }
                    db.insert_log(parsed)
                    collected += 1
            except Exception as e:
                pass
                
    return collected


def collect_linux(db, max_lines=5000):
    collected = 0
    # Try journalctl
    rc, out, err = _run_cmd(f"journalctl -n {max_lines} -o short")
    if rc == 0 and out:
        for line in out.splitlines():
            if not line.strip():
                continue
            parsed = parse_log_line(line)
            db.insert_log(parsed)
            collected += 1
        return collected
    # fallback to reading common files
    candidates = ['/var/log/syslog', '/var/log/messages', '/var/log/auth.log']
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                    lines = fh.readlines()[-max_lines:]
                    for line in lines:
                        parsed = parse_log_line(line)
                        db.insert_log(parsed)
                        collected += 1
            except PermissionError as e:
                # skip if not permitted
                continue
    return collected


def collect_and_analyze(db_path=None, max_items=1000):
    db_path = db_path or os.environ.get('LOGDB_PATH', 'logs.db')
    db = LogDB(db_path)
    sys = platform.system().lower()
    start = time.time()
    if 'windows' in sys:
        collected = collect_windows(db, max_events=max_items)
    else:
        collected = collect_linux(db, max_lines=max_items)
    analyzer = Analyzer(db)
    # train and run
    trained = analyzer.train()
    analysis = analyzer.run_analysis()
    elapsed = time.time() - start
    return {'collected': collected, 'trained': trained, 'analysis': analysis, 'elapsed_sec': elapsed}


if __name__ == '__main__':
    # quick CLI for local runs
    out = collect_and_analyze()
    print(out)
