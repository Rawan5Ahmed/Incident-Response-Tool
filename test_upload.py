import requests

url = 'http://127.0.0.1:5000/upload'
files = {'logfile': ('test.csv', 'Date,Level,Message\n2023-01-01,INFO,Test', 'text/csv')}

try:
    r = requests.post(url, files=files)
    print(f"Status Code: {r.status_code}")
    print(f"Content Type: {r.headers.get('Content-Type')}")
    print("Response Body HEAD:")
    print(r.text[:500])
except Exception as e:
    print(e)
