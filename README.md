# Log Analyzer

A simple Flask-based log collection and analysis tool with GUI and charts.

Features
- Upload log files (text or JSON lines)
- Store logs in SQLite
- Parse timestamps, levels, and messages
- Train an IsolationForest model and detect anomalies
- Basic dashboard with Chart.js visualizations

Quickstart
1. Create a virtualenv: `python -m venv venv` and activate it
2. Install: `pip install -r requirements.txt`
3. Run: `python app.py`
4. Open `http://localhost:5000` in your browser

Testing
- Run unit tests: `pytest tests/`

Tailing usage
- Start tailing a file: `curl -X POST -H "Content-Type: application/json" -d '{"path":"/path/to/file.log"}' http://localhost:5000/api/tail/start`
- Stop tailing: `curl -X POST http://localhost:5000/api/tail/stop`

Collect & Analyze (automatic)
- POST JSON to `/api/collect_and_analyze` to detect host OS, fetch system logs (Event Viewer on Windows, journalctl or /var/log on Linux), ingest and run the model. Example:
  - `curl -X POST -H "Content-Type: application/json" -d '{"max_items":1000}' http://localhost:5000/api/collect_and_analyze`
- NOTE: Reading system logs may require elevated permissions (Administrator / root). If a command like `journalctl` or `wevtutil` isn't available or permission is denied, the endpoint will return an informative error.

Scheduled collection
- Start scheduled collection: `POST /api/schedule/start` with JSON `{"interval_sec": 300, "max_items": 1000}` to run collection every 300 seconds.
- Stop scheduled collection: `POST /api/schedule/stop`
- Status: `GET /api/schedule/status` (returns whether running and last run summary)
- NOTE: The scheduler runs in-process (BackgroundScheduler). For production, consider running using a process manager (systemd, Windows Service, or Docker) and ensure permissions to read system logs.

Supervised training
- POST JSON to `/api/train_supervised` with `{"labels": [{"id": 123, "label": 1}, ...]}` to train a supervised model from labeled rows in the DB.
- Quick demo: run `python scripts/label_and_train.py` after uploading logs and running `/api/analyze` once to auto-select anomalies for labeling.

Notes & next improvements
- Add tailing/agent for live ingestion
- Provide labeled training data for supervised detection
- Add time-series charts and filtering
- Add user authentication and RBAC

