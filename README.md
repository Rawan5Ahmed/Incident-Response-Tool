## Log Analyzer

A Python-based Log Analyzer and Incident Response (IR) Tool that simulates collects logs, analyzes events, detects anomalies using machine learning, and supports automated incident response actions with evidence collection.

Features

Log Analysis & Event Classification: . Collects and parses logs . Machine-learning based detection of normal vs suspicious events
Incident Response Workflow: . Full SOC workflow: Detection → Analysis → Containment → Recovery
Containment Actions: . Trigger or simulate response actions (block IP, stop process)
Digital Evidence Collection: . Automatically stores evidence for each incident
Web Interface: . Upload logs, view analysis results, and monitor alerts
Alerting System: . Sends alerts when suspicious activity is detected
Project Structure

log-analyzer/

├── app.py # Main application / web interface

├── logdb.py # Log database handling

├── ir_workflow.py # Incident response workflow management

├── event_classifier.py # ML-based event classification

├── containment.py # Containment actions (safe or execute)

├── evidence_collector.py # Collect and store digital evidence

├── alerts.py # Alerting for suspicious activity

├── requirements.txt # Python dependencies

├── evidence/ # Folder to store collected evidence

├── index.html # Web interface template

└── main.js # Frontend JS logic

Quickstart

Clone the repository: git clone https://github.com/your-username/log-analyzer.git cd log-analyzer
Create a virtual environment: python -m venv venv source venv/bin/activate # Linux / macOS venv\Scripts\activate # Windows
Install dependencies: pip install -r requirements.txt
Run the application: python app.py
Incident Response Workflow

Detection –> Logs are collected and monitored
Analysis –> Events are classified (normal / suspicious)
Containment –> Actions triggered or simulated
Evidence –> Logs and metadata are stored in the evidence/ folder
Alerting –> Notifications sent for suspicious events
