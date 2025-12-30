from flask import Flask, request, render_template, jsonify, send_from_directory, send_file
from flask_cors import CORS
import os
import json
from logdb import LogDB
from model import Analyzer
from parsers import parse_log_line
import threading

# IR Workflow imports
from ir_workflow import IRWorkflowManager
from evidence_collector import EvidenceCollector
from containment import ContainmentEngine

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

DB_PATH = os.environ.get('LOGDB_PATH', 'logs.db')
logdb = LogDB(DB_PATH)
analyzer = Analyzer(logdb)

# Initialize IR workflow components
ir_manager = IRWorkflowManager(logdb)
evidence_collector = EvidenceCollector('./evidence')
containment_engine = ContainmentEngine(mode='simulate')

@app.route('/debug')
def debug_status():
    with logdb._conn() as c:
        row_count = c.execute("SELECT count(*) FROM logs").fetchone()[0]
        scored_count = c.execute("SELECT count(*) FROM logs WHERE anomaly_score IS NOT NULL").fetchone()[0]
    return jsonify({
        'db_path': DB_PATH,
        'db_size_mb': os.path.getsize(DB_PATH) / 1024 / 1024 if os.path.exists(DB_PATH) else 0,
        'row_count': row_count,
        'scored_count': scored_count,
        'model_loaded': analyzer.model is not None,
        'supervised': analyzer.supervised
    })

@app.route('/')
def index():
    return render_template('index.html')

import csv
import io
from parsers import parse_log_line, _normalize_ts, _normalize_level

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('logfile')
    if not f:
        return "No file", 400
    
    filename = f.filename.lower()
    content_str = f.read().decode('utf-8', errors='replace')
    inserted = 0

    ALLOWED_EXTENSIONS = {'.log', '.txt', '.csv', '.tsv', '.evt', '.evtx'}
    if not any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        return jsonify({'error': 'Invalid file type. Only .log, .txt, .csv, .tsv allowed.'}), 400

    if filename.endswith('.csv') or filename.endswith('.tsv'):
        # Robust CSV/TSV Parsing Logic
        try:
            # Pre-process: skip comment lines (common in Zeek/security logs) 
            # and find the header line.
            lines = content_str.splitlines()
            data_lines = [l for l in lines if not l.startswith('#')]
            
            if not data_lines:
                return jsonify({'error': 'File appears empty after skipping comments'}), 400

            # Use the first valid line to guess delimiter
            sample = '\n'.join(data_lines[:5])
            try:
                dialect = csv.Sniffer().sniff(sample)
            except:
                # Fallback to comma if sniffing fails
                class Dialect: delimiter = ','
                dialect = Dialect()

            f_io = io.StringIO('\n'.join(data_lines))
            reader = csv.DictReader(f_io, dialect=dialect)
            
            # Helper to strip whitespace from keys
            # (Sometimes headers have spaces e.g. " Date ")
            if reader.fieldnames:
                reader.fieldnames = [x.strip() for x in reader.fieldnames]
            else:
                return jsonify({'error': 'CSV header missing or unreadable'}), 400
            
            batch = []

            # Heuristic mapping for common CSV columns
            def get_val(row, keys):
                for k in keys:
                    # case-insensitive match
                    for row_k in row.keys():
                        if row_k and row_k.lower() == k.lower():
                            return row[row_k]
                return None

            for row in reader:
                ts = get_val(row, ['TimeCreated', 'Date', 'Time', 'Timestamp'])
                lvl_raw = get_val(row, ['LevelDisplayName', 'Level', 'Severity', 'Type'])
                status_code = get_val(row, ['Status', 'StatusCode', 'Code', 'SC'])
                
                # Try to map numeric status code to level if standard level is missing or numeric
                mapped_level = None
                
                # Check directly found level first
                if lvl_raw and not lvl_raw.isdigit():
                     mapped_level = lvl_raw
                
                # If no text level, try status code
                if not mapped_level and status_code and str(status_code).isdigit():
                    sc = int(status_code)
                    if 500 <= sc < 600: mapped_level = 'ERROR'
                    elif 400 <= sc < 500: mapped_level = 'WARNING'
                    elif 200 <= sc < 400: mapped_level = 'INFO'
                
                # Fallback: if lvl_raw was just "404" or "500"
                if not mapped_level and lvl_raw and str(lvl_raw).isdigit():
                     sc = int(lvl_raw)
                     if 500 <= sc < 600: mapped_level = 'ERROR'
                     elif 400 <= sc < 500: mapped_level = 'WARNING'
                     elif 200 <= sc < 400: mapped_level = 'INFO'

                msg = get_val(row, ['Message', 'Description', 'EventData', 'Payload']) or str(row)
                
                parsed = {
                    'raw': str(row),
                    'ts': _normalize_ts(ts),
                    'level': _normalize_level(mapped_level or lvl_raw),
                    'message': msg
                }
                batch.append(parsed)
                inserted += 1
            
            if batch:
                logdb.insert_logs_bulk(batch)
                
        except Exception as e:
            return jsonify({'error': f'Failed to parse CSV: {str(e)}'}), 400
    else:
            # Standard Line-by-line Parsing
        content = content_str.splitlines()
        batch = []
        for line in content:
            parsed = parse_log_line(line)
            batch.append(parsed)
            inserted += 1
        
        if batch:
            logdb.insert_logs_bulk(batch)

    return jsonify({'inserted': inserted})

@app.route('/api/logs/clear', methods=['POST'])
def api_logs_clear():
    logdb.clear_logs()
    return jsonify({'status': 'cleared'})

@app.route('/api/logs', methods=['GET'])
def api_logs():
    limit = int(request.args.get('limit', 500))
    logs = logdb.get_logs(limit=limit)
    return jsonify(logs)

@app.route('/api/stats/severity', methods=['GET'])
def api_stats_severity():
    counts = logdb.get_severity_counts()
    return jsonify(counts)

@app.route('/api/train', methods=['POST'])
def api_train():
    result = analyzer.train()
    return jsonify({'status':'trained', 'trained_samples': result})

@app.route('/api/train_supervised', methods=['POST'])
def api_train_supervised():
    payload = request.json or {}
    labeled = payload.get('labels')
    if not labeled or not isinstance(labeled, list):
        return jsonify({'error':'labels list required'}), 400
    cnt = analyzer.train_supervised(labeled)
    return jsonify({'status':'trained_supervised', 'trained_samples': cnt})

@app.route('/api/analyze', methods=['GET'])
def api_analyze():
    # Run analysis and auto-create incidents
    result = analyzer.run_analysis()
    anomalies = result.get('anomalies', [])
    
    # Auto-create incidents for high-severity anomalies
    if anomalies:
        incident_ids = ir_manager.auto_create_incidents_from_anomalies(anomalies)
        result['incidents_created'] = len(incident_ids)
    
    return jsonify(result)

# Quick collect-and-analyze: detect host OS, collect appropriate system logs, ingest and analyze
from collector import collect_and_analyze

@app.route('/api/collect_and_analyze', methods=['POST'])
def api_collect_and_analyze():
    payload = request.json or {}
    db_path = payload.get('db_path') or DB_PATH
    max_items = int(payload.get('max_items', 1000))
    try:
        result = collect_and_analyze(db_path, max_items)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Scheduled collection using APScheduler
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import threading

scheduler = BackgroundScheduler()
scheduler_lock = threading.Lock()
_scheduler_job = None
last_collect_result = None

def _collect_job(max_items=1000):
    global last_collect_result
    try:
        res = collect_and_analyze(DB_PATH, max_items)
        last_collect_result = res
        return res
    except Exception as e:
        last_collect_result = {'error': str(e)}
        return last_collect_result

@app.route('/api/schedule/start', methods=['POST'])
def api_schedule_start():
    payload = request.json or {}
    # Enforce a 30-second minimum to avoid the "job skipped" errors
    interval = max(30, int(payload.get('interval_sec', 300)))
    max_items = int(payload.get('max_items', 1000))
    with scheduler_lock:
        global _scheduler_job
        if _scheduler_job is not None:
            return jsonify({'running': True, 'interval_sec': interval}), 200
        
        _scheduler_job = scheduler.add_job(_collect_job, trigger=IntervalTrigger(seconds=interval), args=[max_items], id='collect_job', replace_existing=True)
        
        # Start if not already running
        if not scheduler.running:
            scheduler.start()
            
    return jsonify({'started': True, 'interval_sec': interval})

@app.route('/api/schedule/stop', methods=['POST'])
def api_schedule_stop():
    with scheduler_lock:
        global _scheduler_job
        if _scheduler_job is None:
            return jsonify({'stopped': False}), 200
        try:
            scheduler.remove_job('collect_job')
        except Exception:
            pass
        _scheduler_job = None
    return jsonify({'stopped': True})

@app.route('/api/schedule/status', methods=['GET'])
def api_schedule_status():
    running = _scheduler_job is not None
    return jsonify({'running': running, 'last_result': last_collect_result})

# Tailing endpoints: start/stop a background file tailer
from tailer import Tailer
tailer = Tailer(logdb)

@app.route('/api/tail/start', methods=['POST'])
def api_tail_start():
    data = request.json or {}
    path = data.get('path')
    if not path:
        return jsonify({'error':'path required'}), 400
    ok = tailer.start(path)
    return jsonify({'started': bool(ok)})

@app.route('/api/tail/stop', methods=['POST'])
def api_tail_stop():
    ok = tailer.stop()
    return jsonify({'stopped': bool(ok)})

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

# ============================================================================
# IR WORKFLOW API ENDPOINTS
# ============================================================================

@app.route('/api/incidents', methods=['GET'])
def api_get_incidents():
    """Get all incidents with optional stage filter"""
    stage = request.args.get('stage')
    limit = int(request.args.get('limit', 100))
    
    incidents = logdb.get_incidents(stage=stage, limit=limit)
    
    # Enrich with event descriptions
    from event_classifier import EventClassifier
    for incident in incidents:
        incident['event_description'] = EventClassifier.get_event_description(
            incident['event_type']
        )
    
    return jsonify(incidents)

@app.route('/api/incidents/<int:incident_id>', methods=['GET'])
def api_get_incident(incident_id):
    """Get detailed incident information"""
    incident = ir_manager.get_incident_with_log(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    # Add timeline
    incident['timeline'] = ir_manager.get_timeline(incident_id)
    
    # Add containment recommendations
    if 'log' in incident:
        recommendations = containment_engine.recommend_actions(
            incident['event_type'],
            incident['log']['message']
        )
        incident['recommended_actions'] = recommendations
    
    return jsonify(incident)

@app.route('/api/incidents/<int:incident_id>/advance', methods=['POST'])
def api_advance_incident(incident_id):
    """Advance incident to next workflow stage"""
    data = request.json or {}
    target_stage = data.get('stage')
    
    if not target_stage:
        return jsonify({'error': 'stage parameter required'}), 400
    
    # Validate stage
    valid_stages = ['Analysis', 'Containment', 'Recovery']
    if target_stage not in valid_stages:
        return jsonify({'error': f'Invalid stage. Must be one of: {valid_stages}'}), 400
    
    # Advance based on target stage
    success = False
    if target_stage == 'Analysis':
        success = ir_manager.advance_to_analysis(incident_id)
    elif target_stage == 'Containment':
        success = ir_manager.advance_to_containment(incident_id)
    elif target_stage == 'Recovery':
        success = ir_manager.advance_to_recovery(incident_id)
    
    if success:
        return jsonify({'status': 'advanced', 'new_stage': target_stage})
    else:
        return jsonify({'error': 'Failed to advance incident'}), 500

@app.route('/api/workflow/summary', methods=['GET'])
def api_workflow_summary():
    """Get IR workflow summary statistics"""
    summary = ir_manager.get_workflow_summary()
    return jsonify(summary)

@app.route('/api/containment/recommend', methods=['POST'])
def api_recommend_containment():
    """Get containment action recommendations"""
    data = request.json or {}
    event_type = data.get('event_type', '')
    message = data.get('message', '')
    
    recommendations = containment_engine.recommend_actions(event_type, message)
    return jsonify({'recommendations': recommendations})

@app.route('/api/containment/execute', methods=['POST'])
def api_execute_containment():
    """Execute (simulate) a containment action"""
    data = request.json or {}
    incident_id = data.get('incident_id')
    action_type = data.get('action_type')
    params = data.get('params', {})
    
    if not incident_id or not action_type:
        return jsonify({'error': 'incident_id and action_type required'}), 400
    
    # Execute the action (simulate mode)
    result = containment_engine.execute_action(action_type, params, incident_id)
    
    # Log the action to the incident
    incident = logdb.get_incident(incident_id)
    if incident:
        # Parse existing actions or create new list
        existing_actions = incident.get('containment_actions')
        if existing_actions:
            try:
                actions_list = json.loads(existing_actions)
            except:
                actions_list = []
        else:
            actions_list = []
        
        actions_list.append(result)
        
        # Update incident
        logdb.update_incident_containment(
            incident_id,
            json.dumps(actions_list),
            'simulated'
        )
    
    return jsonify(result)

@app.route('/api/evidence/create/<int:incident_id>', methods=['POST'])
def api_create_evidence(incident_id):
    """Create evidence folder for an incident"""
    incident = ir_manager.get_incident_with_log(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    # Create evidence folder
    try:
        folder_path = evidence_collector.create_evidence_folder(incident_id, incident)
        
        # Update incident with evidence folder path
        logdb.update_incident_evidence(incident_id, folder_path)
        
        return jsonify({
            'status': 'created',
            'folder_path': folder_path,
            'incident_id': incident_id
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/evidence/<int:incident_id>', methods=['GET'])
def api_get_evidence(incident_id):
    """Get evidence folder path for an incident"""
    incident = logdb.get_incident(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    evidence_folder = incident.get('evidence_folder')
    if not evidence_folder:
        return jsonify({'error': 'No evidence folder created yet'}), 404
    
    return jsonify({
        'incident_id': incident_id,
        'evidence_folder': evidence_folder,
        'exists': os.path.exists(evidence_folder)
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
