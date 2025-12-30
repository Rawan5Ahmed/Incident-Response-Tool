import requests
import sys

API = 'http://localhost:5000'

def main():
    print("--- Log Analyzer Interactive Trainer ---")
    print(f"Connecting to {API}...")
    
    try:
        r = requests.get(API + '/api/analyze')
        if r.status_code != 200:
            print('Failed to fetch anomalies:', r.text)
            return
    except Exception as e:
        print("Error connecting to server. Is app.py running?")
        print(e)
        return

    js = r.json()
    anoms = js.get('anomalies', [])
    
    if not anoms:
        print("No anomalies found to label! Good job.")
        return

    print(f"Found {len(anoms)} anomalies.\n")
    
    labels = []
    
    for i, a in enumerate(anoms):
        print(f"\nItem {i+1}/{len(anoms)}")
        print(f"Score: {a.get('score', 0):.4f}")
        print(f"Message: {a.get('message')}")
        
        while True:
            choice = input("Is this an Attack? [y]es / [n]o / [s]kip / [q]uit: ").lower().strip()
            if choice in ('y', 'yes'):
                labels.append({'id': a['id'], 'label': 1})
                break
            elif choice in ('n', 'no'):
                labels.append({'id': a['id'], 'label': 0})
                break
            elif choice in ('s', 'skip'):
                break
            elif choice in ('q', 'quit'):
                submit_labels(labels)
                print("Bye!")
                return
            else:
                print("Invalid choice.")
    
    submit_labels(labels)

def submit_labels(labels):
    if not labels:
        print("\nNo labels to submit.")
        return
        
    print(f"\nSubmitting {len(labels)} labels to the Brain...")
    try:
        resp = requests.post(API + '/api/train_supervised', json={'labels': labels})
        if resp.status_code == 200:
            js = resp.json()
            print(f"Success! Model trained on {js.get('trained_samples')} supervised samples.")
            print("The model is now smarter. Run 'Analyze' again to see updated scores.")
        else:
            print("Error uploading labels:", resp.text)
    except Exception as e:
        print("Network error submitting labels:", e)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
