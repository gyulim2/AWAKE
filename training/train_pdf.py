"""PDF 악성 분류 모델 학습 — 재현 가능한 스크립트.

    python training/train_pdf.py            # models/pdf_model.joblib, models/pdf_model_card.json 생성

예전 노트북(training/notebooks_legacy/pdf_ml.ipynb)과 달라진 점
  1. SMOTE를 데이터 분할 *전에* 적용하던 것을 학습 fold 안에서만 적용 (테스트셋에 합성 샘플이 섞이던 누수 제거)
  2. 스케일러·피처 선택·모델을 하나의 Pipeline으로 저장 → 추론 코드가 같은 전처리를 그대로 재현
  3. 피처 이름 목록을 awake.pdf_features.FEATURES 하나로 고정 (학습/추론 불일치 방지)
  4. 단일 분할 정확도 대신 반복 층화 교차검증 지표(평균±표준편차)를 모델 카드에 기록
"""
from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import VarianceThreshold
from sklearn.model_selection import RepeatedStratifiedKFold, cross_validate

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from awake.pdf_features import CONTAINS_TEXT_MAP, FEATURES, UNKNOWN  # noqa: E402

DATA = REPO / "training" / "data"
SEED = 42


def _to_number(v):
    """원본 CSV 값 정리: '1(1)'처럼 pdfid 16진 인코딩 개수가 붙은 값은 앞 숫자만, 'Except'는 UNKNOWN."""
    if isinstance(v, str):
        if v in CONTAINS_TEXT_MAP:
            return CONTAINS_TEXT_MAP[v]
        m = re.match(r"\s*(-?\d+)", v)
        return float(m.group(1)) if m else UNKNOWN
    return v


def load_dataset() -> tuple[pd.DataFrame, pd.Series, dict]:
    ben = pd.read_csv(DATA / "result_ben.csv").assign(label=0)
    mal = pd.read_csv(DATA / "result_mal.csv").assign(label=1)
    stats = {"raw_benign": len(ben), "raw_malicious": len(mal)}

    # 같은 파일(SHA1)이 양쪽 라벨에 다 있으면 판단 불가 → 제거
    both = set(ben["name"]) & set(mal["name"])
    df = pd.concat([ben, mal], ignore_index=True)
    df = df[~df["name"].isin(both)]
    df = df.drop_duplicates(subset="name")
    stats["dropped_conflicting_hash"] = len(both)

    # pdfid 분석이 실패한 행(구조 피처가 비어 있음)과 크기 0인 파일 제거
    before = len(df)
    df = df[df["obj"].notna() & (df["pdfsize"] > 0)]
    stats["dropped_unparsed"] = before - len(df)

    X = df[FEATURES].apply(lambda col: col.map(_to_number)).astype(float)
    y = df["label"].astype(int)
    stats["used_benign"] = int((y == 0).sum())
    stats["used_malicious"] = int((y == 1).sum())
    return X, y, stats


def build_pipeline() -> Pipeline:
    # 트리 모델이라 스케일링은 필요 없다. 상수 피처 제거 → (학습 fold에서만) SMOTE → RandomForest
    return Pipeline([
        ("drop_constant", VarianceThreshold(threshold=0.0)),
        ("smote", SMOTE(random_state=SEED)),
        ("model", RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight=None, random_state=SEED, n_jobs=-1)),
    ])


def main() -> None:
    X, y, stats = load_dataset()
    print("dataset:", stats)

    cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=5, random_state=SEED)
    scoring = {
        "accuracy": "accuracy",
        "balanced_accuracy": "balanced_accuracy",
        "precision_malicious": "precision",
        "recall_malicious": "recall",
        "f1_malicious": "f1",
        "roc_auc": "roc_auc",
    }
    res = cross_validate(build_pipeline(), X, y, cv=cv, scoring=scoring, n_jobs=-1)
    metrics = {
        k: {"mean": round(float(np.mean(res[f"test_{k}"])), 4), "std": round(float(np.std(res[f"test_{k}"])), 4)}
        for k in scoring
    }
    for k, v in metrics.items():
        print(f"  {k:20s} {v['mean']:.3f} ± {v['std']:.3f}")

    final = build_pipeline().fit(X, y)
    rf = final.named_steps["model"]
    kept = np.array(FEATURES)[final.named_steps["drop_constant"].get_support()]
    importance = sorted(zip(kept, rf.feature_importances_), key=lambda t: -t[1])

    out = REPO / "models"
    out.mkdir(exist_ok=True)
    joblib.dump({"pipeline": final, "features": FEATURES}, out / "pdf_model.joblib", compress=3)

    card = {
        "model": "RandomForest (imblearn Pipeline: VarianceThreshold → SMOTE → RandomForest)",
        "trained_on": str(date.today()),
        "sklearn_version": sklearn.__version__,
        "data": stats,
        "features": FEATURES,
        "evaluation": "RepeatedStratifiedKFold(5 folds × 5 repeats), SMOTE는 학습 fold에만 적용",
        "metrics": metrics,
        "top_features": [[n, round(float(w), 4)] for n, w in importance[:10]],
        "caveats": [
            "데이터가 작다(정상 PDF가 약 100개). 수치는 이 데이터셋 기준이며 실제 메일 환경 성능을 보장하지 않는다.",
            "정상/악성 샘플의 출처가 달라 파일 크기 등 출처 특성을 학습했을 가능성이 있다.",
            "학습 CSV는 2024년 PyMuPDF로 추출됐다. 'metadata size' 등은 라이브러리 버전에 따라 값이 조금 달라질 수 있다.",
        ],
    }
    (out / "pdf_model_card.json").write_text(json.dumps(card, ensure_ascii=False, indent=2), encoding="utf-8")
    print("saved:", out / "pdf_model.joblib")


if __name__ == "__main__":
    main()
