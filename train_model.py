"""
PhishGuard — Model Trainer
Trains a Random Forest on the Kaggle phishing dataset.
Saves model + scaler to models/
"""

import os, sys, json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score, accuracy_score)
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from feature_extractor import extract_features, FEATURE_NAMES

DATASET_PATH = "dataset/phishing.csv"
MODEL_DIR    = "models"

os.makedirs(MODEL_DIR, exist_ok=True)


def load_dataset():
    if not os.path.exists(DATASET_PATH):
        print(f"[ERROR] Dataset not found at {DATASET_PATH}")
        print("Download from: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset")
        sys.exit(1)
    df = pd.read_csv(DATASET_PATH)
    print(f"[INFO] Dataset loaded: {df.shape[0]} rows, {df.shape[1]} cols")
    return df


def build_feature_matrix(df: pd.DataFrame):
    """If dataset has a 'url' column, re-extract features. Otherwise use existing cols."""
    if 'url' in df.columns:
        print("[INFO] Extracting features from URLs (this may take a minute)...")
        records = df['url'].apply(extract_features).tolist()
        X = pd.DataFrame(records, columns=FEATURE_NAMES)
        y = df['label'] if 'label' in df.columns else df.iloc[:, -1]
    else:
        # Use dataset's own feature columns
        feature_cols = [c for c in df.columns if c not in ('label', 'status', 'url', 'id')]
        X = df[feature_cols]
        y = df['label'] if 'label' in df.columns else df['status']
    return X, y


def train():
    df = load_dataset()
    X, y = build_feature_matrix(df)

    print(f"[INFO] Features: {X.shape[1]}, Samples: {X.shape[0]}")
    print(f"[INFO] Label distribution:\n{y.value_counts()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    print("\n[INFO] Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=200, max_depth=None,
                                 random_state=42, n_jobs=-1)
    rf.fit(X_train_s, y_train)

    y_pred = rf.predict(X_test_s)
    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, rf.predict_proba(X_test_s)[:, 1])

    print(f"\n{'='*50}")
    print(f"  Accuracy : {acc*100:.2f}%")
    print(f"  ROC-AUC  : {auc:.4f}")
    print(f"{'='*50}")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    # Cross-validation
    cv = cross_val_score(rf, scaler.transform(X), y, cv=5, scoring='accuracy')
    print(f"[INFO] 5-Fold CV Accuracy: {cv.mean()*100:.2f}% ± {cv.std()*100:.2f}%")

    # Save model + metadata
    joblib.dump(rf, f"{MODEL_DIR}/phishguard_rf.pkl")
    joblib.dump(scaler, f"{MODEL_DIR}/scaler.pkl")

    meta = {
        'accuracy': round(acc, 4),
        'roc_auc': round(auc, 4),
        'cv_mean': round(cv.mean(), 4),
        'cv_std': round(cv.std(), 4),
        'feature_names': list(X.columns),
        'n_train': len(X_train),
        'n_test': len(X_test),
    }
    with open(f"{MODEL_DIR}/metadata.json", 'w') as f:
        json.dump(meta, f, indent=2)

    print(f"\n[OK] Model saved → {MODEL_DIR}/phishguard_rf.pkl")
    _plot_importance(rf, list(X.columns))
    return rf, scaler


def _plot_importance(model, feature_names):
    imp = model.feature_importances_
    idx = np.argsort(imp)[::-1][:15]
    plt.figure(figsize=(10, 6))
    plt.title("Top 15 Feature Importances — PhishGuard RF")
    plt.bar(range(len(idx)), imp[idx])
    plt.xticks(range(len(idx)), [feature_names[i] for i in idx], rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(f"{MODEL_DIR}/feature_importance.png", dpi=150)
    print(f"[OK] Feature importance plot saved → {MODEL_DIR}/feature_importance.png")


if __name__ == '__main__':
    train()
