from collector import collect_and_analyze
import tempfile


def test_collect_detects_platform_and_runs():
    # run with a temp DB; this checks it doesn't crash on the CI platform
    with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
        res = collect_and_analyze(db_path=tmp.name, max_items=10)
        assert 'collected' in res
        assert 'analysis' in res
