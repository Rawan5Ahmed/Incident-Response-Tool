import os
import tempfile
from logdb import LogDB
from model import Analyzer


def test_train_and_analyze():
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    db = LogDB(path)
    sample_lines = [
        {'ts':'t1','level':'INFO','message':'normal operation ok','raw':'normal'},
        {'ts':'t2','level':'INFO','message':'normal operation ok','raw':'normal'},
        {'ts':'t3','level':'ERROR','message':'critical failure something','raw':'fail'},
    ]
    for s in sample_lines:
        db.insert_log(s)
    analyzer = Analyzer(db)
    trained = analyzer.train()
    assert trained >= 1
    out = analyzer.run_analysis()
    assert 'total' in out
    assert out['total'] >= 1
    # cleanup
    os.remove(path)
