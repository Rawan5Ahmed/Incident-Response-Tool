from parsers import parse_log_line


def test_normalize_ts_and_level():
    line = '2025-12-23 12:01:24 ERROR Failed to connect to DB: timeout'
    p = parse_log_line(line)
    assert p['ts'] is not None
    assert p['level'] == 'ERROR'
    assert 'Failed to connect' in p['message']

    line2 = '{"timestamp":"2025-12-23T12:03:00Z","level":"warn","message":"something"}'
    p2 = parse_log_line(line2)
    assert p2['level'] == 'WARNING'
    assert p2['ts'].startswith('2025-12-23T12:03:00')
