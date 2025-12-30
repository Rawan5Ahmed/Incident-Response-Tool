from parsers import parse_log_line


def test_parse_json_line():
    line = '{"timestamp":"2025-12-23T12:03:00Z","level":"ERROR","message":"boom"}'
    p = parse_log_line(line)
    assert p['level'] == 'ERROR'
    assert 'boom' in p['message']


def test_parse_text_line():
    line = '2025-12-23 12:01:24 ERROR Failed to connect to DB: timeout'
    p = parse_log_line(line)
    assert p['level'] in ('ERROR', 'WARN', 'INFO')
    assert 'Failed to connect' in p['message']
