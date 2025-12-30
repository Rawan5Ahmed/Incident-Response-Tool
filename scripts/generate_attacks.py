import csv
import random
import datetime

OUTPUT_FILE = 'generated_attacks.csv'
LINES = 1000

# Templates
IPS = {
    'China': ['203.0.113.1', '14.215.177.38', '180.149.132.47'],
    'Russia': ['109.252.1.2', '95.31.18.119', '188.162.64.1'],
    'USA': ['192.168.1.5', '10.0.0.2', '54.239.28.1'],
    'Brazil': ['200.147.67.142', '177.71.128.0'],
    'France': ['54.38.0.0', '195.154.21.0']
}

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
    'Mozilla/5.0 (Linux; Android 10; SM-G960U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36',
    'python-requests/2.25.1', # Bot
    'Nmap Scripting Engine', # Scanner
    'Nikto/2.1.6' # Scanner
]

ATTACK_PATTERNS = [
    ('GET', '/admin.php', 404, 'Web Scan'),
    ('POST', '/login', 403, 'Brute Force'),
    ('GET', '/search?q=\' OR 1=1 --', 200, 'SQL Injection'),
    ('GET', '/../../etc/passwd', 403, 'Path Traversal'),
    ('POST', '/api/upload', 500, 'Malicious Upload (Crash)'),
    ('GET', '/wp-admin/install.php', 404, 'CMS Scan'),
    ('GET', '/shell.php', 404, 'Backdoor Check'),
]

NORMAL_PATTERNS = [
    ('GET', '/index.html', 200, 'Browse'),
    ('GET', '/about', 200, 'Browse'),
    ('GET', '/contact', 200, 'Browse'),
    ('POST', '/login', 200, 'Login Success'),
    ('GET', '/static/css/style.css', 200, 'Resource'),
    ('GET', '/static/js/main.js', 200, 'Resource'),
    ('GET', '/images/logo.png', 200, 'Resource'),
]

print(f"Generating {LINES} log lines...")

with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    # Header
    writer.writerow(['Timestamp', 'IP', 'Method', 'Status', 'Size', 'UserAgent', 'Country', 'Message'])
    
    start_time = datetime.datetime(2025, 1, 1, 0, 0, 0)
    
    for i in range(LINES):
        # Time increment
        start_time += datetime.timedelta(seconds=random.randint(1, 120))
        ts = start_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Decide if Attack (30% chance) or Normal (70%)
        is_attack = random.random() < 0.3
        
        if is_attack:
            country = random.choice(['China', 'Russia', 'Brazil', 'France'])
            ip = random.choice(IPS[country])
            pattern = random.choice(ATTACK_PATTERNS)
            ua = random.choice(USER_AGENTS[3:]) if random.random() < 0.8 else random.choice(USER_AGENTS[:3]) # Mostly bot UAs
            msg = f"{pattern[0]} {pattern[1]} HTTP/1.1" # Raw message style
        else:
            country = 'USA'
            ip = random.choice(IPS['USA'])
            pattern = random.choice(NORMAL_PATTERNS)
            ua = random.choice(USER_AGENTS[:3])
            msg = f"{pattern[0]} {pattern[1]} HTTP/1.1"
            
        method, url, status, note = pattern
        size = random.randint(0, 5000)
        
        # Write Row
        writer.writerow([ts, ip, method, status, size, ua, country, msg])

print(f"Done! Saved to {OUTPUT_FILE}")
print("Upload this file to Log Analyzer to start training.")
