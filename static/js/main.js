document.addEventListener('DOMContentLoaded', () => {

  async function postFormData(url, fd) {
    const resp = await fetch(url, { method: 'POST', body: fd });
    return resp.json();
  }

  let alertsEnabled = false;
  const enableAlertsBtn = document.getElementById('enableAlertsBtn');
  if (enableAlertsBtn) {

    enableAlertsBtn.addEventListener('click', () => {
      if (!alertsEnabled) {
        Notification.requestPermission().then(permission => {
          if (permission === 'granted') {
            alertsEnabled = true;
            enableAlertsBtn.textContent = '🔔 Alerts Enabled';
            enableAlertsBtn.classList.replace('btn-outline-primary', 'btn-success');
            sendAlert('Alerts Active', 'You will now receive notifications for high-severity anomalies.');
          }
        });
      } else {
        alertsEnabled = false;
        enableAlertsBtn.textContent = '🔕 Enable Alerts';
        enableAlertsBtn.classList.replace('btn-success', 'btn-outline-primary');
      }
    });
  }

  function sendAlert(title, message) {
    if (alertsEnabled) {
      new Notification(title, { body: message, icon: '/static/img/alert.png' });
    }
  }

  // Check elements before attaching listeners to prevent JS errors blocking subsequent code
  const uploadForm = document.getElementById('uploadForm');
  if (uploadForm) {
    uploadForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fileInput = document.getElementById('logfile');
      if (!fileInput.files.length) return alert('Choose a file');

      const uploadBtn = e.target.querySelector('button');
      const oldText = uploadBtn.textContent;
      uploadBtn.textContent = 'Uploading...';
      uploadBtn.disabled = true;

      try {
        const fd = new FormData();
        fd.append('logfile', fileInput.files[0]);
        await postFormData('/upload', fd);

        // Trigger Full Workflow
        await fetch('/api/train', { method: 'POST' });
        const ar = await fetch('/api/analyze').then(r => r.json());

        updateAnomalyList(ar.anomalies);
        updateChart(ar.anomalies);
        await loadLogs();

        sendAlert('Upload Complete', `Processed and analyzed new log data.`);
      } catch (err) {
        alert('Error during upload: ' + err);
      } finally {
        uploadBtn.textContent = oldText;
        uploadBtn.disabled = false;
      }
    });
  }

  const forceAnalyzeBtn = document.getElementById('forceAnalyzeBtn');
  if (forceAnalyzeBtn) {
    forceAnalyzeBtn.addEventListener('click', async () => {
      const btn = forceAnalyzeBtn;
      btn.textContent = 'Processing...';
      btn.disabled = true;
      try {
        await fetch('/api/train', { method: 'POST' });
        const ar = await fetch('/api/analyze').then(r => r.json());
        updateAnomalyList(ar.anomalies);
        updateChart(ar.anomalies);
        await loadLogs();
        alert('Deep Scan Complete!');
      } catch (e) {
        alert('Scan failed: ' + e);
      } finally {
        btn.textContent = 'Force Full Scan';
        btn.disabled = false;
      }
    });
  }

  const clearLogsBtn = document.getElementById('clearLogsBtn');
  if (clearLogsBtn) {
    clearLogsBtn.addEventListener('click', async () => {
      // REMOVED CONFIRM dialog explicitly
      try {
        const r = await fetch('/api/logs/clear', { method: 'POST' }).then(r => r.json());
        if (r.status === 'cleared') {
          // UI RESET - Complete Wipe
          const pre = document.getElementById('logsPre'); if (pre) pre.textContent = '';
          updateAnomalyList([]);
          updateChart([]);
          updateLevelChart([]);

          const incTable = document.getElementById('incidentsTable');
          if (incTable) incTable.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No active incidents</td></tr>';

          const wfCounts = ['detectionCount', 'analysisCount', 'containmentCount', 'recoveryCount'];
          wfCounts.forEach(id => { const el = document.getElementById(id); if (el) el.textContent = '0'; });

          const chartSummary = document.getElementById('severitySummary');
          if (chartSummary) chartSummary.innerHTML = '<p class="text-center small text-muted">Upload logs to see results</p>';

          const noDataText = document.getElementById('noDataText');
          if (noDataText) noDataText.classList.remove('d-none');

          const chartContainer = document.getElementById('severityChartContainer');
          if (chartContainer) chartContainer.classList.add('d-none');

          checkStatus(); // Reset header counters
          alert('System Reset Complete. Database cleared.');
        }
      } catch (e) {
        alert('Failed to clear logs: ' + e);
      }
    });
  }

  const trainBtn = document.getElementById('trainBtn');
  if (trainBtn) trainBtn.addEventListener('click', async () => {
    const r = await fetch('/api/train', { method: 'POST' }).then(r => r.json());
    alert('Trained on ' + r.trained_samples + ' samples');
  });

  const analyzeBtn = document.getElementById('analyzeBtn');
  if (analyzeBtn) analyzeBtn.addEventListener('click', async () => {
    const r = await fetch('/api/analyze').then(r => r.json());
    alert('Found ' + r.anomalies.length + ' anomalies. Created ' + (r.incidents_created || 0) + ' incidents.');
    updateAnomalyList(r.anomalies);
    updateChart(r.anomalies);
    loadIncidents();
    updateWorkflowStatus();
  });

  async function loadLogs() {
    // 1. Load Logs for Table
    const logs = await fetch('/api/logs?limit=500').then(r => r.json());
    const pre = document.getElementById('logsPre');
    if (pre) pre.textContent = logs.map(l => (l.ts || '') + ' ' + (l.level || '') + ' ' + l.message).join('\n');

    // 2. Load Stats for Chart (Full DB)
    const stats = await fetch('/api/stats/severity').then(r => r.json());
    updateLevelChart(stats);

    return logs;
  }

  // Helper to toggle visibility
  function toggleDetails(btn) {
    const li = btn.closest('li');
    const detailsDiv = li.querySelector('.raw-details');

    if (detailsDiv.classList.contains('d-none')) {
      detailsDiv.classList.remove('d-none');
      btn.textContent = 'Hide Details';
      btn.classList.remove('btn-outline-secondary');
      btn.classList.add('btn-secondary');
    } else {
      detailsDiv.classList.add('d-none');
      btn.textContent = 'Details';
      btn.classList.add('btn-outline-secondary');
      btn.classList.remove('btn-secondary');
    }
  }
  window.toggleDetails = toggleDetails;

  function renderLogCard(message) {
    const detailsBtn = `<button class="btn btn-sm btn-outline-secondary ms-2" style="font-size: 0.7rem;" onclick="toggleDetails(this)">Details</button>`;
    const rawDetails = `<div class="raw-details mt-2 p-2 bg-dark text-light font-monospace rounded d-none" style="font-size: 0.7rem; word-break: break-all;">${message}</div>`;

    if (message.includes(',')) {
      const parts = message.split(',');
      const ip = parts.find(p => /^\d{1,3}(\.\d{1,3}){3}$/.test(p.trim()));
      const method = parts.find(p => /^(GET|POST|PUT|DELETE|HEAD)$/i.test(p.trim()));
      const status = parts.find(p => /^[1-5]\d{2}$/.test(p.trim()));
      const country = parts.find(p => /^[A-Z][a-z]+$/.test(p.trim()) && p.length > 3 && !p.includes('Chrome') && !p.includes('Safari'));

      if (ip || method || status) {
        let statusColor = 'secondary';
        if (status) {
          if (status.startsWith('2')) statusColor = 'success';
          if (status.startsWith('4')) statusColor = 'warning';
          if (status.startsWith('5')) statusColor = 'danger';
        }

        return `
               <div class="d-flex justify-content-between align-items-start">
                 <div>
                   <div class="mb-1">
                       <strong>${country ? '[' + country + '] ' : ''}</strong> 
                       <span class="text-primary font-monospace">${ip || 'Unknown IP'}</span>
                   </div>
                   <div class="small text-muted text-truncate" style="max-width: 400px;">${message}</div>
                 </div>
                 <div class="text-end">
                   <div>
                       ${method ? `<span class="badge bg-secondary me-1">${method}</span>` : ''}
                       ${status ? `<span class="badge bg-${statusColor}">${status}</span>` : ''}
                   </div>
                   ${detailsBtn}
                 </div>
               </div>
               ${rawDetails}
             `;
      }
    }

    const WIN_EVENT_DESCRIPTIONS = {
      '4624': 'Successful Logon',
      '4625': 'Failed Logon (Invalid Credentials)',
      '4634': 'Account Logged Off',
      '4648': 'Logon using explicit credentials',
      '4672': 'Special Privileges Assigned (Admin Login)',
      '4720': 'New User Account Created',
      '4722': 'User Account Enabled',
      '4723': 'User Account Password Change Attempt',
      '4724': 'User Account Password Reset Attempt',
      '4725': 'User Account Disabled',
      '4726': 'User Account Deleted',
      '4728': 'User added to Security-enabled Global Group',
      '4732': 'User added to Security-enabled Local Group'
    };

    if (message.trim().startsWith("{'") && (message.includes("Event ID") || message.includes("'Source':"))) {
      try {
        let eventIdMatch = message.match(/'Event ID':\s*'(\d+)'/);
        if (!eventIdMatch) eventIdMatch = message.match(/'Source':\s*'(\d+)'/);
        const eventId = eventIdMatch ? eventIdMatch[1] : 'Unknown';

        let taskMatch = message.match(/'Message':\s*'([^']*)'/);
        if (!taskMatch) taskMatch = message.match(/'Task Category':\s*'([^']*)'/);

        let taskRaw = taskMatch ? taskMatch[1] : '';
        let summary = WIN_EVENT_DESCRIPTIONS[eventId] || '';
        const realText = taskRaw.replace(/\\r\\n/g, '\n').replace(/\\t/g, '    ').replace(/\\'/g, "'");

        if (!summary) {
          summary = realText.split('\n')[0].substring(0, 80) + (realText.length > 80 ? '...' : '');
          if (!summary || summary.trim().length < 5) summary = "Windows Event " + eventId;
        }

        const richDetails = `<div class="raw-details mt-2 p-3 bg-light border rounded font-monospace d-none" style="white-space: pre-wrap; font-size: 0.75rem;">${realText}</div>`;

        return `
                    <div class="d-flex justify-content-between align-items-start">
                        <div>
                            <div>
                                <span class="badge bg-primary me-2">WinEvent</span>
                                <strong>ID: ${eventId}</strong>
                            </div>
                            <div class="small text-muted mt-1">Source: Windows Security Auditing</div>
                        </div>
                        <div>${detailsBtn}</div>
                    </div>
                    <div class="mt-2 p-2 text-dark small">
                        <span class="fw-bold text-primary">Description:</span> <span class="fw-bold">${summary}</span>
                    </div>
                    ${richDetails}
                `;
      } catch (e) { }
    }

    return `
            <div class="d-flex justify-content-between align-items-center">
                <div class="text-truncate" style="max-width: 80%;">${message}</div>
                ${detailsBtn}
            </div>
            ${rawDetails}
        `;
  }

  // Constants defined inside or accessible scope
  const MITIGATION_MATRIC = [
    { regex: /failed password|authentication failure|bad credentials/i, action: 'Block IP', command: 'netsh advfirewall firewall add rule name="Block IP" dir=in action=block remoteip=' },
    { regex: /code\s*404|status\s*404/i, action: 'Block Scanning IP', command: 'netsh advfirewall firewall add rule name="Block Scanner" dir=in action=block remoteip=' },
    { regex: /user add|group add/i, action: 'Review Privileges', command: 'netplwiz' },
    { regex: /sudo|admin/i, action: 'Audit Session', command: 'query user' },
    { regex: /sql injection|union select|script>/i, action: 'Block Web Attack', command: 'netsh advfirewall firewall add rule name="Block SQLi" dir=in action=block remoteip=' }
  ];

  const EXPLANATIONS = [
    { regex: /code\s*404|status\s*404|http\/1\.\d"\s*404/i, text: '🔍 Web Scanning: The visitor is looking for files that do not exist (e.g., trying to find admin pages).' },
    { regex: /code\s*500|status\s*500/i, text: 'Internal Server Error (Crash or Bug).' },
    { regex: /failed password|authentication failure|bad credentials/i, text: '💡 Possible Brute Force Attempt: Someone is failing to login.' },
    { regex: /segmentation fault|segfault/i, text: '💥 Critical Error: A program crashed due to memory issues.' },
    { regex: /connection refused|connection timed out/i, text: 'Network Error: Server is blocking requests or is down.' },
    { regex: /usb.*scan/i, text: 'Hardware Event: USB Device scanning.' },
    { regex: /user add|group add/i, text: '⚠️ Account Change: A new user or group was created.' },
    { regex: /sudo/i, text: 'Admin Action: Someone executed a Super-User command.' }
  ];

  // Simulation helper attached to window scope for onclick access
  window.simulateContainment = async (action, btn) => {
    const originalText = btn.textContent;

    btn.textContent = '⚡ Executing...';
    btn.disabled = true;
    btn.className = 'btn btn-xs btn-warning shadow-sm';

    // Fake delay for realism
    await new Promise(r => setTimeout(r, 1200));

    btn.textContent = '✔ Applied';
    btn.className = 'btn btn-xs btn-success shadow-sm';

    // Show notification
    sendAlert('Containment Action Success', `Successfully executed: ${action}`);

    // Disable after success
    setTimeout(() => {
      btn.disabled = true;
    }, 500);
  }

  function updateAnomalyList(anoms) {
    const ul = document.getElementById('anomalyList');
    if (!ul) return;

    ul.innerHTML = '';

    const criticals = anoms.filter(a => a.score > 0.8);
    if (criticals.length > 0) {
      sendAlert('High Severity Detected', `Found ${criticals.length} critical anomalies in the latest analysis.`);
    }

    anoms.slice(0, 50).forEach(a => {
      const li = document.createElement('li');
      li.className = 'list-group-item';
      let sevColor = 'info';
      let sevLabel = 'Low';
      if (a.score > 0.8) { sevColor = 'danger'; sevLabel = 'HIGH'; }
      else if (a.score > 0.5) { sevColor = 'warning'; sevLabel = 'MEDIUM'; }

      const displayMsg = renderLogCard(a.message);

      // Find explanation
      let explanation = '';
      for (const exp of EXPLANATIONS) {
        if (exp.regex.test(a.message)) {
          explanation = `<div class="mt-2 p-2 bg-light border-start border-4 border-info small text-dark"><strong>💡 Insight:</strong> ${exp.text}</div>`;
          break;
        }
      }

      // Find Mitigation
      let mitigation = '';
      for (const mit of MITIGATION_MATRIC) {
        if (mit.regex.test(a.message)) {
          let cmd = mit.command;
          // Extract IP if present in message
          const ipMatch = a.message.match(/\d{1,3}(\.\d{1,3}){3}/);
          if (ipMatch) cmd += ipMatch[0];

          mitigation = `
                    <div class="mt-2 alert alert-secondary border-0 p-2 small">
                        <div class="d-flex justify-content-between align-items-center">
                            <div><span class="badge bg-dark me-2">Response</span> <strong>${mit.action}</strong></div>
                             <button class="btn btn-xs btn-danger shadow-sm" onclick="window.simulateContainment('${mit.action}', this)">
                                ⚡ Execute
                            </button>
                        </div>
                        <code class="d-block mt-1 bg-white p-1 rounded border text-muted">${cmd}</code>
                    </div>
                `;
          break;
        }
      }

      li.innerHTML = `
          <div class="d-flex justify-content-between align-items-center mb-1">
            <div>
                <span class="badge bg-${sevColor} rounded-pill me-2">${sevLabel}</span>
                <span class="badge bg-light text-dark border" title="Raw Score">${a.score.toFixed(2)}</span>
            </div>
          </div>
          ${displayMsg}
          ${explanation}
          ${mitigation}
        `;
      ul.appendChild(li);
    });
  }

  function updateLevelChart(statsOrLogs) {
    let counts = { 'High': 0, 'Medium': 0, 'Low': 0, 'Pending': 0 };

    // Check if we received the raw stats object or a list of logs
    if (Array.isArray(statsOrLogs)) {
      // Old fallback logic if needed
      statsOrLogs.forEach(l => {
        let score = l.anomaly_score !== undefined ? l.anomaly_score : l.score;
        if (score !== null && score !== undefined) {
          if (score > 0.8) counts['High']++;
          else if (score > 0.5) counts['Medium']++;
          else counts['Low']++;
        } else counts['Pending']++;
      });
    } else if (statsOrLogs && typeof statsOrLogs === 'object') {
      // Use pre-computed stats
      counts = statsOrLogs;
    }

    const noDataEl = document.getElementById('noDataText');
    const containerEl = document.getElementById('severityChartContainer');
    const summaryEl = document.getElementById('severitySummary');

    // Calculate total from counts
    const total = (counts['High'] || 0) + (counts['Medium'] || 0) + (counts['Low'] || 0) + (counts['Pending'] || 0);

    if (total === 0) {
      if (noDataEl) noDataEl.classList.remove('d-none');
      if (containerEl) containerEl.classList.add('d-none');
      if (summaryEl) summaryEl.innerHTML = '<p class="text-center small text-muted">Upload logs to see results</p>';
      return;
    } else {
      if (noDataEl) noDataEl.classList.add('d-none');
      if (containerEl) containerEl.classList.remove('d-none');
      if (summaryEl) {
        summaryEl.innerHTML = `
              <div class="d-flex justify-content-around mt-2 p-2 bg-white rounded border shadow-sm flex-wrap w-100">
               <span class="badge badge-high">${counts['High'] || 0} High</span>
               <span class="badge badge-medium">${counts['Medium'] || 0} Med</span>
               <span class="badge badge-low">${counts['Low'] || 0} Low</span>
              </div>
            `;
      }
    }

    const labels = Object.keys(counts).filter(k => counts[k] > 0 || k !== 'Pending');
    const data = labels.map(k => counts[k]);
    const ctx = document.getElementById('levelChart');
    if (!ctx) return;

    if (window.levelChartInstance) {
      window.levelChartInstance.destroy();
    }

    const colorMap = {
      'High': '#dc3545',
      'Medium': '#ffc107',
      'Low': '#0dcaf0',
      'Pending': '#adb5bd'
    };

    window.levelChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{ data: data, backgroundColor: labels.map(l => colorMap[l] || '#000'), borderWidth: 1 }]
      },
      options: {
        maintainAspectRatio: false,
        responsive: true,
        plugins: { legend: { display: false } },
        cutout: '70%'
      }
    });
  }

  let chart = null;
  function updateChart(anoms) {
    const labels = anoms.map(a => a.id);
    const data = anoms.map(a => a.score);
    const ctx = document.getElementById('anomalyChart');
    if (!ctx) return;
    if (!chart) {
      chart = new Chart(ctx, {
        type: 'bar',
        data: { labels: labels, datasets: [{ label: 'Anomaly score', data: data, backgroundColor: 'rgba(255,99,132,0.5)' }] },
        options: { scales: { y: { beginAtZero: false } } }
      });
    } else {
      chart.data.labels = labels; chart.data.datasets[0].data = data; chart.update();
    }
  }

  // filter and refresh handlers
  const refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadLogs);

  const lvlFilter = document.getElementById('levelFilter');
  if (lvlFilter) lvlFilter.addEventListener('change', () => {
    const lvl = lvlFilter.value;
    fetch('/api/logs?limit=500').then(r => r.json()).then(logs => {
      let filtered = logs;
      if (lvl) filtered = logs.filter(l => l.level === lvl);
      const pre = document.getElementById('logsPre');
      if (pre) pre.textContent = filtered.map(l => (l.ts || '') + ' ' + (l.level || '') + ' ' + l.message).join('\n');
      updateLevelChart(logs);
    });
  });

  // schedule functions
  let schedulePoller = null;
  async function startSchedule() {
    let interval = Number(document.getElementById('schedInterval').value) || 300;
    const max_items = Number(document.getElementById('schedMaxItems').value) || 1000;
    if (interval < 30) { interval = 30; document.getElementById('schedInterval').value = 30; }
    const r = await fetch('/api/schedule/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interval_sec: interval, max_items: max_items }) }).then(r => r.json());
    if (r.started || r.running) {
      const el = document.getElementById('schedStatus'); if (el) el.textContent = 'Running';
      pollScheduleStatus();
    } else { alert('Failed to start scheduler'); }
  }

  async function stopSchedule() {
    const r = await fetch('/api/schedule/stop', { method: 'POST' }).then(r => r.json());
    if (r.stopped) {
      const el = document.getElementById('schedStatus'); if (el) el.textContent = 'Stopped';
      if (schedulePoller) { clearInterval(schedulePoller); schedulePoller = null; }
    }
  }

  async function getScheduleStatus() {
    try {
      const r = await fetch('/api/schedule/status').then(r => r.json());
      const el = document.getElementById('schedStatus'); if (el) el.textContent = r.running ? 'Running' : 'Stopped';

      const lr = r.last_result;
      const lastEl = document.getElementById('schedLastResult');
      if (lastEl && lr) {
        lastEl.textContent = `Collected: ${lr.collected}, Trained: ${lr.trained}, Time: ${lr.elapsed_sec.toFixed(1)}s`;
      }

      if (r.running && !schedulePoller) { schedulePoller = setInterval(getScheduleStatus, 30000); }
    } catch (e) { }
  }
  function pollScheduleStatus() { getScheduleStatus(); if (!schedulePoller) { schedulePoller = setInterval(getScheduleStatus, 30000); } }

  const schedStartBtn = document.getElementById('schedStartBtn');
  if (schedStartBtn) schedStartBtn.addEventListener('click', startSchedule);
  const schedStopBtn = document.getElementById('schedStopBtn');
  if (schedStopBtn) schedStopBtn.addEventListener('click', stopSchedule);

  getScheduleStatus();
  loadLogs();

  async function checkStatus() {
    try {
      const r = await fetch('/debug').then(r => r.json());
      const dbRows = document.getElementById('dbRows'); if (dbRows) dbRows.textContent = r.row_count || 0;
      const dbScored = document.getElementById('dbScored'); if (dbScored) dbScored.textContent = r.scored_count || 0;
      const dbSize = document.getElementById('dbSize'); if (dbSize) dbSize.textContent = (r.db_size_mb || 0).toFixed(2) + ' MB';

      const mEl = document.getElementById('modelStatus');
      if (mEl) {
        if (r.model_loaded) {
          mEl.textContent = r.supervised ? 'SUPERVISED' : 'UNSUPERVISED';
          mEl.className = 'text-success fw-bold';
        } else {
          mEl.textContent = 'OFFLINE';
          mEl.className = 'text-danger fw-bold';
        }
      }
    } catch (e) { }
  }
  setInterval(checkStatus, 5000);
  checkStatus();

  const loadDemoBtn = document.getElementById('loadDemoBtn');
  if (loadDemoBtn) loadDemoBtn.addEventListener('click', async () => {
    const btn = loadDemoBtn; btn.disabled = true;
    try {
      const demoContent = "2023-11-01 12:00:00 INFO User login successful\\n2023-11-01 12:05:00 ERROR 404 access to /admin/config\\n2023-11-01 12:10:00 CRITICAL SQL Injection detected: ' OR 1=1\\n";
      const blob = new Blob([demoContent], { type: 'text/plain' });
      const fd = new FormData();
      fd.append('logfile', blob, 'demo_logs.txt');
      await postFormData('/upload', fd);
      await fetch('/api/train', { method: 'POST' });
      const ar = await fetch('/api/analyze').then(r => r.json());
      updateAnomalyList(ar.anomalies);
      updateChart(ar.anomalies);
      await loadLogs();
      alert('Demo Logs Loaded!');
    } catch (e) { alert('Demo failed ' + e); } finally { btn.disabled = false; checkStatus(); }
  });

  const refreshDashBtn = document.getElementById('refreshDashBtn');
  if (refreshDashBtn) refreshDashBtn.addEventListener('click', async () => {
    loadLogs();
    const r = await fetch('/api/analyze').then(r => r.json());
    updateAnomalyList(r.anomalies);
    updateChart(r.anomalies);
    checkStatus();
  });

  const downloadEvidenceBtn = document.getElementById('downloadEvidenceBtn');
  if (downloadEvidenceBtn) downloadEvidenceBtn.addEventListener('click', async () => {
    try {
      const logs = await fetch('/api/logs?limit=1000').then(r => r.json());
      const anomalies = logs.filter(l => l.is_anomaly);
      let report = `LOG ANALYZER EVIDENCE REPORT\nGenerated: ${new Date().toLocaleString()}\n`;
      anomalies.forEach((a, i) => {
        report += `[${i + 1}] ${a.message}\n`;
      });
      const blob = new Blob([report], { type: 'text/plain' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'evidence.txt';
      document.body.appendChild(a); a.click();
    } catch (e) { alert('Export failed'); }
  });

  // IR Workflow
  async function loadIncidents() {
    try {
      const incidents = await fetch('/api/incidents?limit=20').then(r => r.json());
      const tbody = document.getElementById('incidentsTable');
      if (!tbody) return;

      if (!incidents || incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No active incidents</td></tr>';
        return;
      }

      tbody.innerHTML = '';
      incidents.forEach(inc => {
        const row = document.createElement('tr');
        let sevBadge = 'info';
        if (inc.severity === 'High') sevBadge = 'danger';
        else if (inc.severity === 'Medium') sevBadge = 'warning';

        let stageBadge = 'success';
        if (inc.current_stage === 'Analysis') stageBadge = 'info';
        else if (inc.current_stage === 'Containment') stageBadge = 'warning';
        else if (inc.current_stage === 'Recovery') stageBadge = 'primary';

        const detected = inc.detected_at ? new Date(inc.detected_at).toLocaleString() : 'N/A';

        // Workflow Action Buttons
        let actionBtn = '';
        if (inc.current_stage === 'Detection') {
          actionBtn = `<button class="btn btn-xs btn-info ms-1" style="font-size:0.6rem;" onclick="advanceIncident(${inc.id}, 'Analysis')">Start Analysis</button>`;
        } else if (inc.current_stage === 'Analysis') {
          actionBtn = `<button class="btn btn-xs btn-warning ms-1" style="font-size:0.6rem;" onclick="advanceIncident(${inc.id}, 'Containment')">Contain</button>`;
        } else if (inc.current_stage === 'Containment') {
          actionBtn = `<button class="btn btn-xs btn-primary ms-1" style="font-size:0.6rem;" onclick="advanceIncident(${inc.id}, 'Recovery')">Recover</button>`;
        }

        row.innerHTML = `
            <td>${inc.id}</td>
            <td><small>${inc.event_description || inc.event_type}</small></td>
            <td><span class="badge bg-${sevBadge}">${inc.severity}</span></td>
            <td><span class="badge bg-${stageBadge}">${inc.current_stage}</span></td>
            <td><small>${detected}</small></td>
            <td>
              ${actionBtn}
            </td>
          `;
        tbody.appendChild(row);
      });
    } catch (e) { console.error('Failed to load incidents:', e); }
  }

  // Workflow Advance Helper
  window.advanceIncident = async (id, stage) => {
    const url = `/api/incidents/${id}/advance`;
    console.log('Advancing incident:', url, stage);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stage: stage })
      });
      console.log('Advance response status:', resp.status);

      if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Server Error (${resp.status}): ${text.substring(0, 100)}...`);
      }

      const r = await resp.json();

      if (r.status === 'advanced') {
        loadIncidents();
        updateWorkflowStatus(); // Update the HUD numbers
      } else {
        alert('Wait, failed to advance: ' + (r.error || 'Unknown'));
      }
    } catch (e) {
      console.error('Advance error:', e);
      alert('Action Failed: ' + e.message);
    }
  }

  async function updateWorkflowStatus() {
    try {
      const summary = await fetch('/api/workflow/summary').then(r => r.json());
      const d = document.getElementById('detectionCount'); if (d) d.textContent = summary.Detection || 0;
      const a = document.getElementById('analysisCount'); if (a) a.textContent = summary.Analysis || 0;
      const c = document.getElementById('containmentCount'); if (c) c.textContent = summary.Containment || 0;
      const r = document.getElementById('recoveryCount'); if (r) r.textContent = summary.Recovery || 0;
    } catch (e) { }
  }

  const refreshIncidentsBtn = document.getElementById('refreshIncidentsBtn');
  if (refreshIncidentsBtn) refreshIncidentsBtn.addEventListener('click', () => { loadIncidents(); updateWorkflowStatus(); });

  loadIncidents();
  updateWorkflowStatus();
  setInterval(updateWorkflowStatus, 10000);

});
