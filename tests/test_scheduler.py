from app import app
import time


def test_schedule_start_stop():
    client = app.test_client()
    # start scheduler with short interval
    rv = client.post('/api/schedule/start', json={'interval_sec': 1, 'max_items': 5})
    assert rv.status_code == 200
    j = rv.get_json()
    assert 'started' in j or 'running' in j

    # check status
    rv2 = client.get('/api/schedule/status')
    assert rv2.status_code == 200
    s = rv2.get_json()
    assert s.get('running') is True

    # allow one run to occur
    time.sleep(1.5)

    # stop scheduler
    rv3 = client.post('/api/schedule/stop')
    assert rv3.status_code == 200
    assert rv3.get_json().get('stopped') is True

    # final status should be stopped
    rv4 = client.get('/api/schedule/status')
    assert rv4.status_code == 200
    assert rv4.get_json().get('running') is False
