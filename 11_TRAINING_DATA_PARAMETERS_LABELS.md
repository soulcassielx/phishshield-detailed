# SECTION 11: TRAINING DATA, PARAMETERS, LABELS, AND HOW EACH MODEL GETS TRAINED

---

## TABLE OF CONTENTS
1. [Overview: Supervised vs Unsupervised in PhishShield](#1-overview)
2. [Model 1: URL DistilBERT — Training Deep Dive](#2-url-distilbert-training)
3. [Model 2: Content DistilBERT — Training Deep Dive](#3-content-distilbert-training)
4. [Model 3: PHP XGBoost — Training Deep Dive](#4-php-xgboost-training)
5. [Model 4: Behavior Isolation Forest — Training Deep Dive](#5-behavior-iforest-training)
6. [Model 5: Zero-Day Isolation Forest — Training Deep Dive](#6-zero-day-iforest-training)
7. [The Master Training Pipeline](#7-master-training-pipeline)
8. [Data Preprocessing Pipeline](#8-data-preprocessing)
9. [Complete Parameter Reference Table](#9-complete-parameter-reference)
10. [Suggested Questions and Answers](#10-suggested-questions-and-answers)

---

## 1. Overview: Supervised vs Unsupervised in PhishShield

### The Two Learning Paradigms

| Paradigm | Models | How It Works | Labels Required? |
|:---|:---|:---|:---|
| **Supervised Learning** | URL DistilBERT, Content DistilBERT, PHP XGBoost | Model learns from LABELED examples. "This URL is phishing (1), this URL is safe (0)." Model maps input → correct label. | YES — each sample needs a 0 or 1 |
| **Unsupervised Learning** | Behavior IForest, Zero-Day IForest | Model learns from UNLABELED data. "These are normal browsing behaviors." Model learns the distribution of normal and flags deviations. | NO — trains on normal examples only |

### Why PhishShield Uses Both

| What Labels Give Us | What Labels DON'T Give Us |
|:---|:---|
| Accurate detection of KNOWN phishing patterns | Detection of UNKNOWN/novel phishing patterns |
| Confident predictions with probability scores | Adaptation to new attack types |
| Direct optimization for phishing vs benign | Handling attacks not in the training distribution |

**Supervised models = detect known threats. Unsupervised models = detect unknown threats.**
**You need BOTH for comprehensive defense.**

---

## 2. Model 1: URL DistilBERT — Training Deep Dive

### What Gets Trained
A DistilBERT transformer model that classifies raw URL strings as benign (0) or phishing (1).

### Training Data Format

| Field | Type | Example (Benign) | Example (Phishing) |
|:---|:---|:---|:---|
| **Input (X)** | Raw URL string | `"https://www.google.com/search/docs/about"` | `"http://paypal-secure-k8d3m2p1.tk/verify"` |
| **Label (y)** | Integer (0 or 1) | `0` (benign) | `1` (malicious) |

### How Training Data Is Created

#### Source 1: Synthetic Data (Default when no real data exists)
```python
# Benign URLs (label=0):
# Template: https://www.{known_domain}/{random_path}
"https://www.google.com/page/docs/about"
"https://www.github.com/search/help"
"https://www.stackoverflow.com/api/docs"

# Malicious URLs (label=1):
# Templates with phishing patterns:
"http://192.168.45.12/login.php?id=abcd1234"      # IP address + .php
"http://paypal-secure-k8d3m2p1.tk/verify"          # Brand + cheap TLD
"http://x7f2k9p3.xyz/wp-admin/login"               # Random domain + admin path
"http://update-account-m4n2b8q1.ml/confirm"        # Credential keywords
"http://free-paypal-abcd1234.cf/claim"              # Free + brand
```

#### Source 2: Real Data (Production training)
- **Phishing URLs:** PhishTank feed, APWG reports, user-reported blacklist (`data/phishing_urls.csv`)
- **Benign URLs:** Alexa/Tranco Top 1M whitelist, user scan results (`data/legit_urls.csv`)

### Labels
| Label | Meaning | Integer Value |
|:---|:---|:---|
| Benign / Safe / Legitimate | Normal website URL | `0` |
| Malicious / Phishing / Suspicious | Phishing or malware URL | `1` |

### Data Preprocessing
```python
preprocessor = DataPreprocessor()

# Step 1: Clean URLs
urls, labels = preprocessor.clean_urls(urls, labels)
# - Remove URLs < 20 characters
# - Deduplicate
# - Unicode normalize (NFKC)
# - Remove URLs without http/https/ftp scheme

# Step 2: Stratified Split (80/10/10)
split = preprocessor.stratified_split(urls, labels)
# train: 80% of data
# val:   10% of data (for early stopping)
# test:  10% of data (for final evaluation)
# Stratified = same ratio of phishing/benign in each split
```

### Training Hyperparameters (Complete List)

| Parameter | Value | What It Controls |
|:---|:---|:---|
| **Optimizer** | AdamW | Adaptive learning rate with weight decay |
| **Learning rate** | 2e-5 (0.00002) | How fast the model updates weights per step |
| **Weight decay** | 0.01 | L2 regularization intensity |
| **Warmup ratio** | 0.15 | First 15% of steps linearly increase LR from 0 to 2e-5 |
| **Gradient clipping** | 0.8 | Max gradient norm before scaling |
| **Epochs** | 5 (max) | Maximum training passes over the data |
| **Batch size** | 64 | Samples processed per gradient update |
| **Max token length** | 128 | Maximum URL tokens fed to model |
| **Dropout rate** | 0.4 | Fraction of neurons randomly disabled during training |
| **Early stopping patience** | 3 | Stop if val loss doesn't improve for 3 epochs |
| **Loss function** | FocalLoss (γ=2.0) | Class-imbalance-aware loss function |
| **Mixed precision** | FP16 (on GPU) | Half-precision forward pass for speed |

### Training Process Step-by-Step
```
1. Initialize DistilBERT from pre-trained "distilbert-base-uncased"
2. Set dropout=0.4 for all dropout layers
3. Tokenize all train/val URLs (WordPiece, pad to 128)
4. Compute class weights from label distribution
5. Create FocalLoss with γ=2.0 and class weights

FOR epoch in 1..5:
    FOR batch in training_data (64 samples per batch):
        a. Forward pass: URL tokens → 6 transformer layers → logits
        b. Compute FocalLoss between logits and true labels
        c. Backward pass: compute gradients
        d. Clip gradients to max norm 0.8
        e. Update weights via AdamW
        f. Step learning rate scheduler
    
    Evaluate on validation set:
        IF val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
        ELSE:
            patience_counter += 1
            IF patience_counter >= 3: STOP (early stopping)

6. Save model weights + tokenizer to disk
```

### Output File
```
models/url_distilbert/
├── config.json           # Model architecture config
├── model.safetensors     # Trained weights (~250MB)
├── tokenizer.json        # Tokenizer vocabulary
├── tokenizer_config.json # Tokenizer configuration
├── special_tokens_map.json
└── vocab.txt             # WordPiece vocabulary (30,522 words)
```

---

## 3. Model 2: Content DistilBERT — Training Deep Dive

### What Gets Trained
A DistilBERT transformer that classifies HTML feature strings as benign (0) or phishing (1).

### Training Data Format

| Field | Type | Example (Benign) | Example (Phishing) |
|:---|:---|:---|:---|
| **Input (X)** | Feature string | `"ext_links:3 inputs:2 scripts:1 title:Welcome to our website page 42"` | `"forms:2 password_fields:1 inputs:5 hidden:3 brand:paypal action:http://evil34.tk/collect iframes:2"` |
| **Label (y)** | Integer (0 or 1) | `0` (benign) | `1` (phishing) |

### How Training Data Differs from URL Model
- URL model trains on **raw URL strings** → tokenized directly
- Content model trains on **pre-extracted feature strings** → NOT raw HTML

### Synthetic Data Generation
```python
# Benign pattern: few features, no brand/password
"ext_links:7 scripts:2 title:Welcome to our website page 88"

# Phishing pattern: forms + password + brand + external action
"forms:1 password_fields:2 inputs:7 hidden:1 brand:google action:http://evil89.tk/collect"
```

### Labels
Identical to URL model: `0 = benign`, `1 = phishing`

### Training Hyperparameters
**Identical to URL model** (same architecture, same optimizer, same loss function). The only difference is the INPUT DATA (feature strings instead of URLs).

### Output File
```
models/content_distilbert/
├── config.json
├── model.safetensors     # ~250MB
├── tokenizer.json
└── ... (same structure as URL model)
```

---

## 4. Model 3: PHP XGBoost — Training Deep Dive

### What Gets Trained
An XGBoost gradient boosted tree ensemble that classifies PHP code feature vectors as benign (0) or malicious (1).

### Training Data Format

| Field | Type | Shape | Description |
|:---|:---|:---|:---|
| **Input (X)** | numpy float64 array | `(n_samples, 8)` | 8 numeric features per PHP file |
| **Label (y)** | numpy float64 array | `(n_samples,)` | 0=benign, 1=malicious |

### The 8 Input Features

| Index | Feature Name | Data Type | Benign Distribution | Malicious Distribution |
|:---|:---|:---|:---|:---|
| 0 | `eval_count` | Integer (Poisson) | Poisson(λ=0.1) → mostly 0 | Poisson(λ=3.0) → avg ~3 |
| 1 | `system_count` | Integer (Poisson) | Poisson(λ=0.05) → mostly 0 | Poisson(λ=2.0) → avg ~2 |
| 2 | `base64_count` | Integer (Poisson) | Poisson(λ=0.2) → mostly 0 | Poisson(λ=4.0) → avg ~4 |
| 3 | `entropy` | Float (Normal) | Normal(μ=3.5, σ=0.5) | Normal(μ=5.2, σ=0.8) |
| 4 | `superglobal_count` | Integer (Poisson) | Poisson(λ=1.0) → avg ~1 | Poisson(λ=4.0) → avg ~4 |
| 5 | `file_write_flag` | Binary (Bernoulli) | Bernoulli(p=0.3) → 30% chance | Bernoulli(p=0.8) → 80% chance |
| 6 | `network_flag` | Binary (Bernoulli) | Bernoulli(p=0.15) → 15% chance | Bernoulli(p=0.6) → 60% chance |
| 7 | `length` | Float (LogNormal) | LogNormal(μ=7, σ=1.0) → ~1100 chars | LogNormal(μ=6, σ=1.5) → variable |

### Labels
| Label | Meaning | Integer Value |
|:---|:---|:---|
| Benign | Normal PHP script (contact forms, CMS code) | `0` |
| Malicious | Webshell, backdoor, credential stealer | `1` |

### Training Process
```
1. Generate or load 2000 PHP feature samples
2. Compute class balance: scale_pos_weight = n_negative / n_positive
3. Fit StandardScaler on training data (mean=0, std=1)
4. Scale all features

5. Stratified 5-Fold Cross Validation:
   FOR fold in 1..5:
       a. Split data into 80% train / 20% val
       b. Create XGBClassifier with all params
       c. Fit with early_stopping_rounds=30 on eval_set
       d. Record fold AUC and F1 score
   Report mean ± std of AUC across folds

6. Train FINAL model on all data (85/15 train/val split)
7. Save model (.json) + scaler (.pkl)
```

### Output Files
```
models/php_xgboost.json          # XGBoost model (35KB)
models/php_xgboost_scaler.pkl    # StandardScaler (1KB)
```

---

## 5. Model 4: Behavior Isolation Forest — Training Deep Dive

### What Gets Trained
An Isolation Forest that learns the distribution of NORMAL web page behavior.

### Training Data Format

| Field | Type | Shape | Description |
|:---|:---|:---|:---|
| **Input (X)** | numpy float64 array | `(n_samples, 10)` | 10 behavioral features per page visit |
| **Label (y)** | **NOT USED IN TRAINING** | N/A | Unsupervised — no labels needed! |

### The 10 Input Features

| Index | Feature Name | Unit | Normal Distribution | What "Anomalous" Looks Like |
|:---|:---|:---|:---|:---|
| 0 | `redirect_count` | count | Poisson(λ=1.5) → avg ~1.5 | 5+ redirects |
| 1 | `post_request_count` | count | Poisson(λ=0.5) → avg ~0.5 | 3+ POST requests |
| 2 | `xhr_request_count` | count | Poisson(λ=2.0) → avg ~2 | 8+ XHR calls |
| 3 | `external_resource_count` | count | Poisson(λ=5.0) → avg ~5 | 20+ external resources |
| 4 | `form_count` | count | Poisson(λ=0.8) → avg ~0.8 | 3+ forms |
| 5 | `hidden_element_count` | count | Poisson(λ=0.5) → avg ~0.5 | 5+ hidden elements |
| 6 | `script_count` | count | Poisson(λ=3.0) → avg ~3 | 8+ script tags |
| 7 | `iframe_count` | count | Poisson(λ=0.3) → avg ~0.3 | 3+ iframes |
| 8 | `page_load_time_ms` | milliseconds | LogNormal(μ=6.5, σ=0.5) → ~665ms | >3000ms |
| 9 | `total_request_count` | count | Poisson(λ=15) → avg ~15 | 50+ total requests |

### WHY NO LABELS?
Isolation Forest is **unsupervised**. It does NOT learn "this is phishing" or "this is safe." Instead:
1. It receives a batch of behavioral data points (assumed to be MOSTLY normal, with ~3% contamination)
2. It builds 200 random isolation trees
3. It learns WHERE the normal data points cluster in 10-dimensional space
4. At inference time, any data point FAR from this cluster = anomalous

**The beauty:** Without ANY labeled phishing data, the model detects phishing through behavioral anomaly — including phishing it has never seen before.

### Training Process
```
1. Collect/generate 2000 behavioral samples (97% normal, 3% anomalous)
2. Fit StandardScaler (mean=0, std=1 per feature)
3. Scale all features
4. Create IsolationForest(n_estimators=200, contamination=0.03)
5. model.fit(X_scaled)  ← NO LABELS PASSED!
6. Verify: ~3% of training data is flagged as anomalous (sanity check)
7. Save model (.pkl) + scaler (.pkl)
```

### Output Files
```
models/behavior_iforest.pkl          # IsolationForest model (~4.3MB)
models/behavior_iforest_scaler.pkl   # StandardScaler (1KB)
```

---

## 6. Model 5: Zero-Day Isolation Forest — Training Deep Dive

### What Gets Trained
An Isolation Forest that learns the distribution of NORMAL URL entropy + length + rare function count.

### Training Data Format

| Field | Type | Shape | Description |
|:---|:---|:---|:---|
| **Input (X)** | numpy float64 array | `(n_samples, 3)` | 3 features per URL analysis |
| **Label (y)** | **NOT USED IN TRAINING** | N/A | Unsupervised |

### The 3 Input Features

| Index | Feature Name | Unit | Normal Distribution | Zero-Day Trigger |
|:---|:---|:---|:---|:---|
| 0 | `entropy` | bits | Normal(μ=3.5, σ=0.5) → 2.5-4.5 | >5.0 (heavily obfuscated) |
| 1 | `length` | characters | LogNormal(μ=7, σ=1.0) → ~50-250 | >500 or <15 |
| 2 | `rare_function_count` | count | Poisson(λ=0.5) → 0-1 | 5+ eval/system calls |

### How Features Are Extracted at Inference

```python
# From url_features.py:
entropy = url_features.get("entropy_full_url", 0)     # Shannon entropy of URL

# From URL length:
length = url_features.get("url_length", 0)

# From PHP analyzer results:
rare_count = sum([
    php_result.get("eval_count", 0),
    php_result.get("system_count", 0),
])

# Combined into feature array:
features = np.array([entropy, length, rare_count], dtype=np.float64)
```

### Training Process
Same as Behavior IForest but with 3 features instead of 10:
```
1. Collect/generate 2000 samples (97% normal, 3% anomalous)
2. Fit StandardScaler
3. IsolationForest(n_estimators=200, contamination=0.03)
4. model.fit(X_scaled)  ← no labels
5. Save model + scaler
```

### Output Files
```
models/zeroday_iforest.pkl    # Combined model + scaler dict (~4.3MB)
```

---

## 7. The Master Training Pipeline

### Complete Training Orchestration
File: `server/training/train_pipeline.py`

```python
class TrainingPipeline:
    def train_all(self, skip_transformers=False):
        """Train ALL 5 models in sequence."""
        
        # 1. PHP XGBoost (fastest: <30s)
        train_php_model()       # Uses synthetic or real PHP feature data
        
        # 2. Behavior IForest (fast: <1s)
        train_behavior_model()  # Uses synthetic or real behavior data
        
        # 3. Zero-Day IForest (fast: <1s)
        train_zero_day_model()  # Uses synthetic or real entropy/length data
        
        # 4. URL DistilBERT (slow: ~45min CPU, ~8min GPU)
        if not skip_transformers:
            train_url_model()   # Uses synthetic or real URL strings
        
        # 5. Content DistilBERT (slow: ~45min CPU, ~8min GPU)
        if not skip_transformers:
            train_content_model()  # Uses synthetic or real feature strings
```

### Training Data Flow

```
                     ┌────────────────────────┐
                     │   Data Sources          │
                     ├────────────────────────┤
                     │ - data/phishing_urls.csv│
                     │ - data/legit_urls.csv   │
                     │ - User scans (feedback) │
                     │ - PhishTank feeds       │
                     │ - Synthetic generation  │
                     └──────────┬─────────────┘
                                │
                     ┌──────────▼─────────────┐
                     │ DataPreprocessor         │
                     ├─────────────────────────┤
                     │ - clean_urls()          │
                     │ - clean_php_data()      │
                     │ - stratified_split()    │
                     │   (80/10/10)            │
                     │ - compute_class_weights │
                     │ - save/load_scaler      │
                     └──────────┬─────────────┘
                                │
              ┌─────────────────┼──────────────────┐
              │                 │                  │
     ┌────────▼──────┐  ┌──────▼───────┐   ┌─────▼───────┐
     │ Supervised     │  │ Supervised   │   │ Supervised  │
     │ URL DistilBERT │  │ Content BERT │   │ PHP XGBoost │
     │                │  │              │   │             │
     │ Input: URLs    │  │ Input: feat  │   │ Input: 8-dim│
     │ Labels: 0/1    │  │ Labels: 0/1  │   │ Labels: 0/1 │
     │ Loss: Focal    │  │ Loss: Focal  │   │ Loss: LogLos│
     │ Optimizer:     │  │ Optimizer:   │   │ Optimizer:  │
     │   AdamW        │  │   AdamW      │   │   XGB Boost │
     └────────────────┘  └──────────────┘   └─────────────┘

              ┌─────────────────┼──────────────────┐
              │                                    │
     ┌────────▼──────────┐          ┌──────────────▼────┐
     │ Unsupervised       │          │ Unsupervised      │
     │ Behavior IForest   │          │ Zero-Day IForest  │
     │                    │          │                   │
     │ Input: 10-dim      │          │ Input: 3-dim      │
     │ Labels: NONE       │          │ Labels: NONE      │
     │ Algorithm:         │          │ Algorithm:        │
     │   Isolation Forest │          │   Isolation Forest│
     │ Learns: "normal"   │          │ Learns: "normal"  │
     └───────────────────┘          └───────────────────┘
```

---

## 8. Data Preprocessing Pipeline

### File: `server/training/preprocess.py`

### URL Cleaning Rules
| Rule | Action | Why |
|:---|:---|:---|
| Length < 20 chars | REMOVE | Too short to be a real URL |
| Duplicate URLs | REMOVE (keep first) | Prevent training bias |
| Unicode normalization | NFKC normalize | Handle homograph attacks |
| No scheme prefix | REMOVE | Must have http://, https://, or ftp:// |

### Stratified Split: 80/10/10
```python
# First split: 80% train vs 20% (val+test)
train, temp = train_test_split(data, test_size=0.20, stratify=labels)

# Second split: 50/50 on the 20% → 10% val, 10% test
val, test = train_test_split(temp, test_size=0.50, stratify=temp_labels)
```

**Stratified** means each split has the SAME ratio of phishing:benign as the original dataset. If the dataset is 30% phishing, then train/val/test are all 30% phishing.

### Class Weight Computation
```python
def compute_class_weights(labels):
    counts = Counter(labels)    # {0: 1400, 1: 600}
    total = len(labels)         # 2000
    n_classes = len(counts)     # 2
    
    weights = {}
    for cls, count in counts.items():
        weights[cls] = total / (n_classes * count)
    
    # weights = {0: 2000/(2*1400) = 0.714, 
    #            1: 2000/(2*600) = 1.667}
    
    return weights
```
Class 1 (phishing) gets weight 1.667 — each phishing sample counts ~2.3x more than a benign sample during training.

---

## 9. Complete Parameter Reference Table

### All Models — Side-by-Side

| Parameter | URL DistilBERT | Content DistilBERT | PHP XGBoost | Behavior IForest | Zero-Day IForest |
|:---|:---|:---|:---|:---|:---|
| **Algorithm** | Transformer (6 layers) | Transformer (6 layers) | Gradient Boosted Trees | Isolation Forest | Isolation Forest |
| **Learning Type** | Supervised | Supervised | Supervised | Unsupervised | Unsupervised |
| **Input Dimensions** | 128 tokens (variable) | 128 tokens (variable) | 8 numeric features | 10 numeric features | 3 numeric features |
| **Output** | P(malicious) [0,1] | P(phishing) [0,1] | P(malicious) [0,1] | Anomaly score [0,1] | is_zero_day + score |
| **Labels** | 0=benign, 1=malicious | 0=benign, 1=phishing | 0=benign, 1=malicious | NONE | NONE |
| **Loss Function** | FocalLoss (γ=2.0) | FocalLoss (γ=2.0) | Binary LogLoss | N/A | N/A |
| **Optimizer** | AdamW | AdamW | XGB gradient descent | N/A | N/A |
| **Learning Rate** | 2e-5 | 2e-5 | 0.03 | N/A | N/A |
| **Epochs/Rounds** | 5 (max) | 5 (max) | 300 trees | N/A | N/A |
| **Batch Size** | 64 | 64 | full dataset | 1024 (max_samples) | 1024 (max_samples) |
| **Regularization** | Dropout=0.4 + L2=0.01 | Dropout=0.4 + L2=0.01 | L2=3.0 + L1=1.0 + γ=1.5 + depth=5 + subsample + colsample | contamination=0.03 | contamination=0.03 |
| **Early Stopping** | patience=3 epochs | patience=3 epochs | 30 rounds | N/A | N/A |
| **Feature Scaling** | N/A (tokenization) | N/A (tokenization) | StandardScaler | StandardScaler | StandardScaler |
| **Train Data Size** | ~20k samples | ~20k samples | ~2k samples | ~2k samples | ~2k samples |
| **Training Time (CPU)** | ~45 min | ~45 min | <30 sec | <1 sec | <1 sec |
| **Training Time (GPU)** | ~8 min | ~8 min | <10 sec | N/A | N/A |
| **Model File Size** | ~250MB | ~250MB | 35KB | 4.3MB | 4.3MB |
| **Inference Latency** | 15-25ms | 15-25ms | <5ms | <1ms | <1ms |
| **Saved Format** | HuggingFace safetensors | HuggingFace safetensors | XGBoost JSON | joblib pickle | joblib pickle |

---

## 10. Suggested Questions and Answers

### Q1: "If the models use synthetic data, how accurate can they really be?"

**Answer:** Synthetic data provides a BASELINE accuracy of ~85-90%. This is sufficient for initial deployment. As real user scans accumulate through the feedback loop (legit_urls.csv / phishing_urls.csv), the models can be retrained on real-world data, pushing accuracy to ~92-97%.

The synthetic data captures the STATISTICAL PROPERTIES of phishing (high entropy URLs, brand keywords, excessive forms/password fields, PHP eval/system calls) — even though the exact URLs are fake, the patterns are real. This is analogous to training a spam filter on template spam emails before deploying it on real email.

### Q2: "The Behavior IForest has contamination=0.03. What if real phishing is 10% of traffic?"

**Answer:** The contamination parameter tells the model "expect 3% of training data to be anomalous." If real phishing is 10%, two things happen:
1. **During training:** The model's threshold is slightly too lenient (it thinks 3% is the boundary, but reality is 10%). Some borderline phishing behavior may be accepted as "normal."
2. **During inference:** The anomaly scores are still valid — truly anomalous pages still get short path lengths. Only the decision THRESHOLD is affected.

**Fix:** Periodically measure actual phishing rate from user reports and adjust contamination accordingly. Or use an adaptive threshold based on score distribution.

### Q3: "Why does DistilBERT use max_length=128 instead of 512?"

**Answer:** URLs are short — 95% of URLs have fewer than 100 characters. With WordPiece tokenization, even a 200-character URL produces ~40-60 tokens. Using max_length=512 would:
- Waste ~75% of each input tensor on padding
- Slow down inference by ~3x (attention is O(n²))
- Not improve accuracy (the extra tokens are all [PAD])

128 tokens captures virtually all URL information while keeping inference fast (15-25ms vs ~60-80ms with 512).

### Q4: "How does the pipeline handle it when a model is not loaded?"

**Answer:** Every model has a safety check:
```python
def predict(self, input):
    if not self.is_loaded or self.model is None:
        return 0.0  # Safe default — model contributes nothing
```
If any model fails to load, it returns 0.0 (no signal). The pipeline's risk fusion formula only considers models that are available:
```python
risk = (Σ score_i * weight_i) / (Σ weight_i for AVAILABLE models)
```
This means the system degrades gracefully — losing one model reduces accuracy but doesn't crash.

### Q5: "Can I retrain just one model without retraining all five?"

**Answer:** YES. Each model is independently trained and saved:
```python
pipeline = TrainingPipeline(output_dir="models")

# Retrain ONLY the URL model with new data:
pipeline.train_url_model(urls=new_urls, labels=new_labels, epochs=3)

# Retrain ONLY the PHP model:
pipeline.train_php_model(X=new_php_features, y=new_php_labels)

# Or retrain ALL:
pipeline.train_all()
```

### Q6: "What happens if the training data is poisoned (attacker adds fake 'safe' labels to phishing URLs)?"

**Answer:** This is a real concern. Currently, PhishShield has LIMITED protection against data poisoning:
- The `/report` endpoint accepts user reports without authentication
- If an attacker floods false "safe" reports for phishing URLs, they could corrupt the training data

**Mitigations needed:**
1. Authentication on the report API
2. Rate limiting on reports
3. Threshold-based reporting (require 3+ users to report before adding to list)
4. Anomaly detection on the reports themselves (detect patterns of false reporting)

### Q7: "Why use FocalLoss instead of regular Cross-Entropy?"

**Answer:** In a typical phishing dataset:
- 70% benign URLs → the model gets very good at predicting "benign"
- 30% phishing URLs → the model under-learns phishing patterns

With regular Cross-Entropy, a model that predicts "benign" for EVERYTHING achieves 70% accuracy — but catches ZERO phishing. This is useless.

FocalLoss fixes this by:
1. **Down-weighting easy examples:** If the model is 95% confident a benign URL is benign, the loss is nearly zero → model doesn't waste learning capacity
2. **Up-weighting hard examples:** If the model is only 30% confident a phishing URL is phishing, the loss is HUGE → model focuses learning here
3. **Class weights amplify this:** Phishing samples get 2.3x weight multiplier on top of focal focusing

### Q8: "How often should models be retrained?"

**Answer:** Depends on the deployment:
- **Static deployment (personal use):** Monthly retraining is sufficient
- **Production API (<10k scans/day):** Weekly retraining with accumulated scan data
- **High-volume service (>100k scans/day):** Daily or continuous retraining using streaming data pipelines

PhishShield currently has NO automated retraining scheduler — this is a manual process. Adding a cron-based retraining pipeline with drift detection (using the existing `DriftDetector` class) is a recommended future improvement.

### Q9: "The Behavior model trains on 97% normal data. Where does 'normal' data come from?"

**Answer:** Two sources:
1. **Synthetic generation:** `BehaviorIsolationForest.generate_synthetic_data()` creates feature vectors with realistic distributions (Poisson for counts, LogNormal for load times)
2. **Real scan data:** As users scan legitimate URLs, the sandbox results provide real behavioral data. Page load times, redirect counts, XHR counts — all from real browsing sessions on real websites

The synthetic data uses published research on "typical" web page behavior metrics to set distribution parameters (λ values for Poisson, μ/σ for LogNormal).

### Q10: "What evaluation metrics should be used for each model type?"

**Answer:**
| Model Type | Primary Metric | Secondary Metrics | Why |
|:---|:---|:---|:---|
| **URL DistilBERT** | F1-Score | Precision, Recall, AUC-ROC | F1 balances precision (avoid FP) and recall (catch all phishing) |
| **Content DistilBERT** | F1-Score | Precision, Recall | Same reasoning |
| **PHP XGBoost** | AUC-ROC | F1, Precision@90%Recall | AUC is robust to threshold selection; important for varying operating points |
| **Behavior IForest** | Anomaly detection rate at 3% FPR | Precision-Recall curve | Must detect anomalies without excessive false alarms |
| **Zero-Day IForest** | Detection rate on held-out anomalies | FPR at fixed detection rate | Zero-day detection is binary — did it catch the attack or not? |
| **Full Pipeline** | End-to-end F1 on mixed dataset | Latency (P50, P95) | Real-world performance = accuracy + speed |
