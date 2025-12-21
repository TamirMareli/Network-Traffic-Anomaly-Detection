# Network Traffic Anomaly Detection with Machine Learning  
### Cyber Bootcamp Final Project (Progress Report)

**Authors:**  
Tamir Mareli, Ilay Romi  

**Program:**  
Cybersecurity Bootcamp  
---

## 1. Introduction

Modern computer networks generate vast amounts of traffic, making manual inspection impractical for detecting malicious behavior.  
As a result, **Network Intrusion Detection Systems (NIDS)** increasingly rely on **machine learning techniques** to automatically identify anomalous traffic patterns that may indicate cyber attacks.

The goal of this project is to design and implement a **network traffic anomaly detection pipeline** using machine learning, based on the **NSL-KDD dataset**, a well-known benchmark dataset for intrusion detection research.

This report documents the progress achieved so far, including dataset exploration, preprocessing, feature engineering, and preparation for model training.

---

## 2. Problem Definition

The task is formulated as a **network traffic anomaly detection problem**, where each network connection is classified as either:

- **Normal traffic**
- **Malicious traffic (Attack)**

Two classification settings are considered:
1. **Binary classification**: Normal vs Attack  
2. **Multi-class classification**: Normal, DoS, Probe, R2L, U2R  

At the current stage of the project, the focus is placed on the **binary anomaly detection formulation**, which aligns well with real-world intrusion detection systems and is more robust given the limited project timeline.

---

## 3. Dataset Description – NSL-KDD

The project uses the **NSL-KDD dataset**, an improved version of the original KDD Cup 1999 dataset, designed to address redundancy and bias issues present in the original benchmark. 

**Key Findings:**
* **Class Balance:** The dataset is relatively balanced (approx. 53% Normal vs. 47% Attack), reducing the immediate need for synthetic oversampling (SMOTE).
* **Correlation Analysis:** A correlation matrix was computed to identify features most strongly associated with malicious activity. 
    * We observed that traffic features related to **synchronization errors** (e.g., `dst_host_srv_serror_rate`, `serror_rate`) show a very strong positive correlation (>0.65) with attacks. This suggests that many attacks in the dataset (likely DoS or Probe) involve manipulating the TCP handshake process.
    * Conversely, features like `same_srv_rate` showed negative correlation, indicating they are more typical of normal traffic.


### 3.1 Dataset Structure

Each sample in the dataset represents a network connection described by **41 features**, including:
- Basic features (e.g., protocol type, duration)
- Content-based features
- Traffic-based statistical features

The dataset includes:
- **Training set:** `KDDTrain+`
- **Test set:** `KDDTest+`

The test set contains attack types that do not appear in the training set, simulating real-world scenarios where previously unseen attacks may occur.

---

## 4. Data Loading and Cleaning

The raw dataset files were loaded into Pandas DataFrames.  
Since the files do not include column headers, feature names were manually defined according to the official NSL-KDD documentation.

To prepare the data for machine learning algorithms, we implemented a structured preprocessing pipeline:
1.  **Categorical Encoding:** Features such as `protocol_type`, `service`, and `flag` were transformed using **One-Hot Encoding**. Crucially, the encoder is configured to handle unknown categories in the test set to prevent runtime errors during inference.
2.  **Feature Scaling:** Numerical features (e.g., `duration`, `src_bytes`) were standardized using `StandardScaler` to ensure that features with large ranges do not dominate the model's objective function.
3.  **Target Mapping:** The 23 distinct attack labels were mapped into 5 major categories (Normal, DoS, Probe, R2L, U2R) to facilitate both binary and multi-class classification tasks.

### 4.1 Missing Values

A thorough inspection revealed:
- No missing (null) values in either the training or test datasets.

### 4.2 Duplicate Samples

Duplicate samples were detected in both datasets.  
To reduce redundancy and potential overfitting, duplicate rows were removed during preprocessing.

### 4.3 Removal of Metadata Attributes

The `difficulty` attribute was removed from the dataset, as it represents meta-information about the complexity of each sample rather than a meaningful feature for model training.

---

## 5. Exploratory Data Analysis (EDA)

### 5.1 Class Distribution

The dataset was reformulated as a binary classification problem:
- **Normal traffic**
- **Attack traffic**

Visualization confirmed that the dataset is relatively balanced, with only a mild deviation between normal and attack traffic.

Although the imbalance is not severe, it motivates the use of evaluation metrics beyond accuracy, such as **recall**, **precision**, and **F1-score**, particularly for the attack class.

---

## 6. Attack Categorization

Each specific attack label in the dataset was mapped to one of four high-level attack categories:
- **DoS (Denial of Service)**
- **Probe**
- **R2L (Remote to Local)**
- **U2R (User to Root)**

Samples labeled as `normal` were assigned to the **Normal** category.

### 6.1 Handling Unseen Attacks in the Test Set

The NSL-KDD test set includes attack types that do not appear in the training data,
simulating real-world zero-day attack scenarios.

During preprocessing, such attack labels are explicitly mapped to an `Unknown` category.
In the binary classification setting, all non-normal traffic—including unknown attacks—
is treated as malicious.

For the multi-class setting, the `Unknown` category is retained and encoded alongside
the standard attack categories, enabling future analysis of unseen attack behavior.

---

## 7. Feature Engineering and Preprocessing

### 7.1 Feature Selection

Target-related variables were excluded from the feature set prior to preprocessing:
- `label`
- `attack_category`

Binary and multi-class targets were stored separately and not included as model inputs.

The remaining features were divided into:
- **Categorical features:** `protocol_type`, `service`, `flag`
- **Numerical features:** all remaining numeric attributes

---

### 7.2 Encoding and Scaling

A preprocessing pipeline was constructed using Scikit-learn:
- Numerical features were standardized using `StandardScaler`.
- Categorical features were encoded using `OneHotEncoder` with `handle_unknown='ignore'`
  to safely process unseen categories in the test set.

To ensure compatibility across different Scikit-learn versions,
the encoder initialization includes a fallback mechanism handling both legacy
and newer parameter conventions.

The preprocessing pipeline was fitted exclusively on the training data and then
applied to both training and test sets, preventing data leakage.

---

### 7.3 Removal of Zero-Variance Features

Numerical features with zero variance were identified and removed.
Such features contain constant values across all samples and do not contribute
any useful information for classification.

The variance check was performed on the training set only, and the same features
were removed from the test set to preserve feature alignment.

---

## 8. Prepared Data for Modeling

After preprocessing:
- Feature matrices were saved as NumPy arrays (`X_train.npy`, `X_test.npy`)
- Target vectors were saved for both binary and multi-class settings
- Feature names were extracted for interpretability
- The preprocessing pipeline was serialized for future inference

A validation step confirmed that class distributions between training and test
sets remain consistent after preprocessing.

---

## 9. Project Structure

The project follows a modular and reproducible structure:

NETWORK-TRAFFIC-ANOMALY-DETECTION/
│
├── data/
│   ├── raw/
│   └── processed/
│       ├── train_cleaned.csv
│       └── test_cleaned.csv
│
├── notebooks/
│   ├── 01_data_exploration.ipynb
│   ├── 02_preprocessing.ipynb
│   ├── 03_model_training.ipynb
│   └── 04_evaluation.ipynb
│
├── results/
│   ├── figures/
│   └── metrics/
│
├── src/
│   ├── preprocessing.py
│   ├── models.py
│   └── evaluation.py
│
├── README.md
├── report.md
└── requirements.txt


This structure enables clear separation between data handling, experimentation, modeling, and evaluation.

---

## 10. Next Steps

The next stages of the project include:
1. Baseline supervised models

2. Unsupervised anomaly detection

3. Evaluation & metrics

4. Error analysis

---

## 11. Conclusion

This report documents the initial stages of a machine-learning-based network traffic anomaly detection system.  
Through careful dataset exploration, preprocessing, and feature engineering, a solid foundation has been established for subsequent modeling and evaluation.

The methodology emphasizes reproducibility, fairness in evaluation, and alignment with real-world intrusion detection challenges.



