from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
import joblib
import os
import numpy as np

MODEL_PATH = 'model.joblib'

class Analyzer:
    def __init__(self, db):
        self.db = db
        self.vectorizer = TfidfVectorizer(max_features=2000)
        self.model = None
        self.supervised = False

    def _get_texts(self):
        rows = self.db.get_messages(limit=None)
        ids = [r[0] for r in rows]
        texts = [r[1] or '' for r in rows]
        return ids, texts

    def train(self, force=False):
        ids, texts = self._get_texts()
        if not texts:
            return 0
        X = self.vectorizer.fit_transform(texts)
        # unsupervised model
        iso = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
        iso.fit(X.toarray())
        self.model = iso
        self.supervised = False
        joblib.dump({'vec': self.vectorizer, 'model': self.model, 'supervised': self.supervised}, MODEL_PATH)
        return len(texts)

    def train_supervised(self, labeled_list):
        # labeled_list: list of {id: id, label: 0/1}
        ids, texts = self._get_texts()
        id_to_text = dict(zip(ids, texts))
        X_texts = []
        y = []
        for item in labeled_list:
            iid = item.get('id')
            label = int(item.get('label', 0))
            if iid in id_to_text:
                X_texts.append(id_to_text[iid])
                y.append(label)
        if not X_texts:
            return 0
        X = self.vectorizer.fit_transform(X_texts)
        clf = LogisticRegression(max_iter=1000)
        clf.fit(X, y)
        self.model = clf
        self.supervised = True
        joblib.dump({'vec': self.vectorizer, 'model': self.model, 'supervised': self.supervised}, MODEL_PATH)
        return len(y)

    def load(self):
        if os.path.exists(MODEL_PATH):
            d = joblib.load(MODEL_PATH)
            self.vectorizer = d['vec']
            self.model = d['model']
            self.supervised = d.get('supervised', False)
            return True
        return False

    def run_analysis(self):
        # return list of anomalies as dicts: id, score, is_anomaly
        ids, texts = self._get_texts()
        if not texts:
            return []
        if not self.model:
            loaded = self.load()
            if not loaded:
                self.train()
        X = self.vectorizer.transform(texts)
        updates = []
        result = []
        if self.supervised:
            probs = self.model.predict_proba(X)[:,1]
            preds = (probs >= 0.5).astype(int)
            for i, id_ in enumerate(ids):
                score = float(probs[i])
                is_anom = int(preds[i])
                updates.append((id_, score, is_anom))
                result.append({'id': id_, 'score': score, 'is_anomaly': is_anom, 'message': texts[i]})
        else:
            scores = self.model.decision_function(X.toarray())
            preds = self.model.predict(X.toarray())
            for i, id_ in enumerate(ids):
                s = float(scores[i])
                is_anom = 1 if preds[i] == -1 else 0
                
                # Normalize IF score to 0-1 where Higher is more anomalous
                # IF raw scores are typically [-0.5, 0.5] where < 0 is anomaly
                if s < 0:
                    # Map [-0.5, 0] to [1.0, 0.5]
                    score = 0.5 + min(0.5, abs(s) * 2)
                else:
                    # Map [0, 0.5] to [0.5, 0]
                    score = max(0, 0.5 - (s * 1.0))
                
                # Heuristic Boost for obvious keywords
                msg_upper = texts[i].upper()
                if 'CRITICAL' in msg_upper or 'SQL INJECTION' in msg_upper or 'ATTACK' in msg_upper:
                    score = max(score, 0.95)
                    is_anom = 1
                elif 'ERROR' in msg_upper or 'FAIL' in msg_upper:
                    score = max(score, 0.6)
                    if score > 0.6: is_anom = 1
                
                updates.append((id_, score, is_anom))
                result.append({'id': id_, 'score': score, 'is_anomaly': is_anom, 'message': texts[i]})

        self.db.update_anomalies(updates)
        anomalies = [r for r in result if r['is_anomaly']]
        
        # Sort anomalies: prioritize highest scores
        anomalies.sort(key=lambda x: x['score'], reverse=True)
            
        return {'total': len(result), 'anomalies': anomalies}
