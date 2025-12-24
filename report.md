# Network Traffic Anomaly Detection with Machine Learning  
## Cyber Bootcamp – Final Project Report

**Authors:**  
Tamir Mareli, Ilay Romi  

**Program:**  
Cybersecurity Bootcamp  

---

## 1. Introduction

Modern computer networks generate massive volumes of traffic, making manual inspection infeasible for detecting malicious activity. Consequently, **Network Intrusion Detection Systems (NIDS)** increasingly rely on **machine learning techniques** to automatically identify anomalous traffic patterns indicative of cyber attacks.

The objective of this project is to design, implement, and evaluate a **machine-learning-based network intrusion detection pipeline**, using the **NSL-KDD dataset** as a benchmark.

The project emphasizes:
- Robust preprocessing with no data leakage
- Recall-oriented detection suitable for real IDS deployment
- Clear separation between data preparation, modeling, and evaluation

---

## 2. Problem Definition

We formulate intrusion detection as a **supervised classification problem** under two settings:

1. **Binary classification**
   - Normal
   - Attack

2. **Multi-class classification (Attack-only)**
   - DoS
   - Probe
   - R2L
   - U2R

The primary focus is on the **binary detection task**, reflecting real-world IDS requirements where **missing an attack is significantly more costly than raising a false alarm**.

---

## 3. Dataset – NSL-KDD

The project uses the **NSL-KDD dataset**, an improved version of the KDD Cup 1999 dataset designed to reduce redundancy and evaluation bias.

### Key Characteristics
- 41 traffic features per connection
- Mix of numerical and categorical attributes
- Test set contains previously unseen attack types, simulating zero-day scenarios

### Class Distribution
- Training set: ~53% Normal, ~47% Attack  
- Test set: skewed toward attacks (~57%)

This distribution shift motivates recall-oriented evaluation.

---

## 4. Data Exploration (Notebook 01)

Exploratory data analysis was conducted to understand:
- Feature distributions
- Class balance
- Correlations between features and attack labels

Key observations:
- TCP error-related features (e.g., `serror_rate`, `dst_host_serror_rate`) strongly correlate with attack traffic
- Rate-based features are especially indicative of DoS and Probe attacks

**Note:**  
Notebook 01 is **exploratory only** and does not produce artifacts consumed by later stages.

---

## 5. Data Preprocessing (Notebook 02)

All preprocessing that produces reusable artifacts is centralized in **Notebook 02**.

### Steps Performed
1. Load raw NSL-KDD files (`KDDTrain+`, `KDDTest+`)
2. Assign feature names according to the official dataset specification
3. Remove metadata attributes (e.g., difficulty level)
4. Map fine-grained attack labels to:
   - `attack_class` (Normal, DoS, Probe, R2L, U2R)
   - `binary_target` (Normal vs Attack)
5. Lock a unified feature schema (41 features)
6. Save cleaned datasets:
   - `data/processed/train_cleaned.csv`
   - `data/processed/test_cleaned.csv`

No scaling, encoding, or model-dependent transformations are applied at this stage to prevent data leakage.

---

## 6. Feature Engineering & Modeling Pipeline (Notebook 03)

### 6.1 Preprocessing Pipeline

All model-dependent preprocessing is implemented using a **Scikit-learn Pipeline**:

- **Numerical features**
  - Safe `log1p` transformation for heavy-tailed attributes
  - RobustScaler to reduce sensitivity to outliers
- **Categorical features**
  - OneHotEncoder with `handle_unknown="ignore"`

The pipeline is fitted **only on training data**.

---

### 6.2 Binary Classification Model

Binary intrusion detection is performed using **XGBoost**, configured to maximize generalization under distribution shift.

Key design choices:
- Shallow trees (`max_depth=3`)
- Strong regularization (`min_child_weight`, `reg_lambda`)
- Recall-biased class weighting
- Early stopping on a dedicated validation set

---

### 6.3 Threshold Selection Strategy

Instead of using the default decision threshold (0.5), the threshold is tuned on a **dedicated threshold set (15%)**.

#### Strategy
- Optimize **F2-score** (recall-weighted)
- Constrain predictions to a realistic **positive rate band**
- Avoid probability calibration due to probability collapse and dataset shift

The resulting threshold is intentionally low, reflecting highly polarized probability outputs while achieving strong recall.

---

## 7. Binary Classification Results (Test Set)

| Metric | Value |
|------|------|
| Accuracy | ~0.895 |
| Attack Recall | **~0.94** |
| Attack Precision | ~0.88 |
| ROC-AUC | ~0.95 |
| PR-AUC | ~0.95 |

These results demonstrate a recall-oriented detector suitable for deployment in intrusion detection systems.

---

## 8. Multi-class Attack Classification

A separate XGBoost model is trained **only on attack samples** to classify attack types.

Performance varies by class:
- DoS and R2L achieve strong precision
- Probe and U2R remain challenging due to limited training samples

This behavior aligns with known limitations of the NSL-KDD dataset.

---

## 9. Online Feature Compatibility

The `FeatureExtractor` module provides a bridge between:
- Offline NSL-KDD training
- Online or simulated network traffic ingestion

It ensures strict schema alignment and safe handling of missing or unknown feature values.

---

## 10. Project Structure

```text
NETWORK-TRAFFIC-ANOMALY-DETECTION/
├── data/
│   ├── raw/
│   └── processed/
│       ├── train_cleaned.csv
│       └── test_cleaned.csv
├── notebooks/
│   ├── 01_data_exploration.ipynb
│   ├── 02_preprocessing.ipynb
│   └── 03_model_training.ipynb
├── src/
│   └── feature_extraction.py
├── results/
├── report.md
└── requirements.txt
