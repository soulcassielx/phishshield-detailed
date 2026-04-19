# SECTION 6: DETAILED ALGORITHM EXPLANATION — DT, XGBoost, ISOLATION FOREST
## Mathematical Foundations and Stage-by-Stage Working

---

## TABLE OF CONTENTS
1. [Decision Trees — The Foundation](#1-decision-trees)
2. [XGBoost — Extreme Gradient Boosting (PHP Model)](#2-xgboost)
3. [Isolation Forest — Anomaly Detection (Behavior + Zero-Day Models)](#3-isolation-forest)
4. [DistilBERT Transformer — Deep Algorithm Walkthrough](#4-distilbert-transformer)
5. [How Each Algorithm Works Stage-by-Stage in PhishShield](#5-stage-by-stage-in-phishshield)

---

## 1. Decision Trees — The Foundation

### What is a Decision Tree?
A decision tree is a supervised learning algorithm that makes predictions by learning a series of IF-THEN-ELSE rules from the data. It's the building block for both XGBoost and Isolation Forest.

### How a Decision Tree is Built

#### Stage 1: Root Node Selection
Given training data with 8 PHP features and binary labels (benign/malicious):

```
Dataset: 2000 PHP files
         ┌─────────────┬──────────────┬─────────┬─────────┐
         │ eval_count   │ system_count │ entropy │ label   │
         ├─────────────┼──────────────┼─────────┼─────────┤
         │ 0            │ 0            │ 3.2     │ benign  │
         │ 3            │ 2            │ 5.1     │ malicious│
         │ 0            │ 0            │ 3.8     │ benign  │
         │ 5            │ 4            │ 5.8     │ malicious│
         │ ...          │ ...          │ ...     │ ...     │
         └─────────────┴──────────────┴─────────┴─────────┘
```

The algorithm evaluates EVERY feature and EVERY possible split value to find the split that maximizes information gain.

#### Stage 2: Information Gain Calculation
For each possible split, calculate the Gini Impurity:

**Gini Impurity formula:**
```
Gini(S) = 1 - Σ(p_i)²
```
Where p_i is the proportion of class i in the set.

**Example: Split on eval_count > 1**
- Left branch (eval_count ≤ 1): 1300 benign, 50 malicious → Gini = 1 - (1300/1350)² - (50/1350)² = 0.072
- Right branch (eval_count > 1): 100 benign, 550 malicious → Gini = 1 - (100/650)² - (550/650)² = 0.260

**Weighted Gini:**
```
Gini_split = (1350/2000) × 0.072 + (650/2000) × 0.260 = 0.049 + 0.085 = 0.134
```

**Compare with split on entropy > 4.2:**
```
Gini_split = (1400/2000) × 0.095 + (600/2000) × 0.185 = 0.067 + 0.056 = 0.123
```

Since 0.123 < 0.134, the entropy split is BETTER (lower Gini = purer partitions).

#### Stage 3: Recursive Splitting
The best split becomes the root node. Then, recursively apply the same process to each branch:

```
                        ┌─────────────────┐
                        │  entropy > 4.2? │ (Root: best first split)
                        └────┬───────┬────┘
                             │       │
                     YES     │       │    NO
                    ┌────────▼──┐ ┌──▼────────┐
                    │eval_cnt>2?│ │    BENIGN  │ (Leaf: 1320/1400 benign)
                    └──┬────┬──┘ └────────────┘
                       │    │
                  YES  │    │  NO
                 ┌─────▼┐ ┌▼────────────────┐
                 │ MAL  │ │  system_cnt > 1? │
                 └──────┘ └──────┬──────┬───┘
                                 │      │
                            ...  │      │  ...
```

#### Stage 4: Stopping Criteria
The tree stops growing when:
- **max_depth reached** (PhishShield: depth=5)
- **min_child_weight** not satisfied (PhishShield: 5 samples minimum)
- **gamma** threshold not met (PhishShield: 1.5 minimum gain)
- All samples in a node belong to the same class
- No further splits reduce Gini impurity

---

## 2. XGBoost — Extreme Gradient Boosting (PHP Model)

### The Core Concept: Gradient Boosting
Instead of building one good tree, build MANY weak trees where each tree corrects the mistakes of all previous trees.

### Stage-by-Stage Algorithm

#### Stage 1: Initialize Base Prediction
```
F_0(x) = log(n_positive / n_negative)
```
For PhishShield with 600 malicious / 1400 benign:
```
F_0(x) = log(600/1400) = log(0.4286) = -0.847
P_0(malicious) = sigmoid(-0.847) = 0.30  (base probability for all samples)
```

#### Stage 2: Compute Residuals (Gradient)
For each training sample, compute the gradient (direction of error):
```
residual_i = y_i - P(malicious | x_i)
```

For a malicious PHP file: `residual = 1 - 0.30 = 0.70` (model is too low, needs to go UP)
For a benign PHP file: `residual = 0 - 0.30 = -0.30` (model is too high, needs to go DOWN)

#### Stage 3: Build Tree 1 to Predict Residuals
Build a decision tree (max_depth=5) to predict these residuals:
```
                    ┌──────────────────┐
                    │ eval_count > 1?  │
                    └───┬──────────┬───┘
                   YES  │          │  NO
              ┌─────────▼──┐  ┌───▼──────────────┐
              │ entropy>4.5│  │ base64_count > 3? │
              └──┬─────┬──┘  └────┬──────────┬───┘
             YES │     │ NO   YES │          │ NO
              ┌──▼─┐ ┌▼──┐  ┌───▼──┐    ┌──▼──┐
              │+0.6│ │+0.3│  │+0.2 │    │-0.25│
              └────┘ └───┘  └──────┘    └─────┘
```

#### Stage 4: Update Model
Add Tree 1's predictions with a small learning rate:
```
F_1(x) = F_0(x) + η × Tree_1(x)
       = -0.847 + 0.03 × Tree_1(x)    (learning rate η=0.03)
```

For a malicious PHP file with eval_count=3, entropy=5.1:
```
F_1(x) = -0.847 + 0.03 × 0.6 = -0.847 + 0.018 = -0.829
P_1(malicious) = sigmoid(-0.829) = 0.304  (slightly increased)
```

#### Stage 5: Compute New Residuals
```
new_residual = 1 - 0.304 = 0.696  (still needs work)
```

#### Stage 6: Build Tree 2, 3, ... 300
Repeat stages 3-5 for each tree. Each tree focuses on the remaining errors:
- Tree 10: Starts catching subtle patterns (system_count + network_flag combinations)
- Tree 50: Fine-tunes boundary cases
- Tree 100: Addresses rare combinations (low eval but high base64 + superglobals)
- Tree 300: Micro-adjustments to decision boundaries

#### Stage 7: Regularization (Why XGBoost Doesn't Overfit)

**L2 Regularization (λ=3.0):**
```
Cost = Loss + λ × Σ(leaf_weight²)
```
Penalizes large leaf weights — prevents any single tree from being too confident.

**L1 Regularization (α=1.0):**
```
Cost = Loss + α × Σ|leaf_weight|
```
Drives small leaf weights to exactly zero — creates sparse trees.

**Gamma (γ=1.5):**
A split ONLY happens if:
```
Gain(split) > γ = 1.5
```
This prevents splits that don't meaningfully improve prediction.

**Subsample (0.85):**
Each tree sees only 85% of the training data (randomly selected). This prevents individual trees from memorizing specific training examples.

**colsample_bytree (0.75):**
Each tree sees only 75% of the 8 features (randomly selected). This prevents trees from always relying on the same top features.

#### Stage 8: Final Prediction
For a new PHP file:
```
F_300(x) = F_0(x) + 0.03 × Σ Tree_k(x) for k=1 to 300

P(malicious) = 1 / (1 + exp(-F_300(x)))
```

**All 300 trees execute simultaneously** (no sequential dependency at inference time).

#### XGBoost's Second-Order Optimization (What Makes it "Extreme")
Standard gradient boosting uses only first-order gradients (residuals). XGBoost also uses **second-order gradients (Hessians)**:

```
Standard: split_gain = (Σ gradients)² / (Σ 1)
XGBoost:  split_gain = (Σ gradients)² / (Σ hessians + λ)
```

The Hessian (second derivative) tells the algorithm HOW CERTAIN it is about the direction of the error. This leads to:
- Better split selection
- More accurate leaf weight estimates
- Faster convergence (needs fewer trees)

---

## 3. Isolation Forest — Anomaly Detection

### The Core Insight
Normal data requires MANY random splits to isolate.
Anomalous data requires FEW random splits to isolate.

This is because anomalies are "few and different" — they sit in sparse regions of the feature space.

### Stage-by-Stage Algorithm (Behavior Model Example)

#### Stage 1: Build Isolation Tree (iTree)

**Input:** 1024 randomly sampled behavioral data points (10 features each)

**Process:**
1. Pick a random feature: `redirect_count` (index 0)
2. Pick a random split value between min(redirect_count)=0 and max(redirect_count)=12: → split at 4.7
3. Send all points with redirect_count < 4.7 to the LEFT, rest to the RIGHT

```
Step 1:    ┌──────────────────────┐
           │ redirect_count < 4.7?│   (random feature, random split)
           └────┬────────────┬────┘
                │            │
           YES (980 pts) NO (44 pts)
```

4. For the LEFT branch (980 points):
   - Pick random feature: `script_count` (index 6)
   - Pick random split at 5.2
   ```
   Step 2:  ┌──────────────────┐
            │ script_count<5.2?│
            └───┬──────────┬──┘
                │          │
           YES (950) NO (30)
   ```

5. Continue recursively until:
   - Each point is alone in a leaf, OR
   - Maximum depth reached: `ceil(log2(1024)) = 10`

#### Stage 2: Path Length Calculation

**Normal data point** (redirect_count=1, script_count=3, ...):
```
redirect_count < 4.7? → YES (go LEFT)
  script_count < 5.2? → YES (go LEFT, 950 points)
    xhr_count < 3.5? → YES (go LEFT, 800 points)
      form_count < 1.2? → YES (go LEFT, 700 points)
        hidden_count < 0.8? → YES (go LEFT, 650 points)
          page_load < 2500? → YES (go LEFT, 600 points)
            ... (continues deeper)
PATH LENGTH = 8 (deeply embedded, hard to isolate)
```

**Anomalous data point** (redirect_count=8, post_count=5, xhr_count=9):
```
redirect_count < 4.7? → NO (go RIGHT, 44 points)
  post_count < 3.2? → NO (go RIGHT, 8 points)
    xhr_count < 6.5? → NO (go RIGHT, 2 points)
      page_load > 5000? → YES (ISOLATED! 1 point)
PATH LENGTH = 4 (quickly isolated, clearly anomalous)
```

#### Stage 3: Average Path Length Across 200 Trees
Each of the 200 trees produces a different path length (because features and splits are random).

```
Normal point:     paths = [8, 7, 9, 8, 7, 8, 9, 8, ...] → average = 8.1
Anomalous point:  paths = [3, 4, 3, 5, 4, 3, 4, 3, ...] → average = 3.6
```

#### Stage 4: Anomaly Score Calculation

The anomaly score is normalized using the expected average path length:
```
c(n) = 2 × H(n-1) - 2(n-1)/n
```
Where H(i) is the harmonic number and n=1024 (subsample size):
```
c(1024) ≈ 12.93
```

**Anomaly score:**
```
s(x, n) = 2^(-E(h(x)) / c(n))
```
Where E(h(x)) is the average path length.

For normal point: `s = 2^(-8.1/12.93) = 2^(-0.626) = 0.647` (close to 0.5 = normal)
For anomalous point: `s = 2^(-3.6/12.93) = 2^(-0.278) = 0.825` (close to 1.0 = anomalous)

#### Stage 5: PhishShield's Score Normalization
Sklearn's `score_samples()` returns the raw anomaly score (negative of the above):
```python
raw_score = model.score_samples(features)  # negative value
# Normal: raw_score ≈ -0.10 to 0.00
# Anomalous: raw_score ≈ -0.50 to -0.70

normalized = max(0.0, min(1.0, -raw_score * 1.5))
```

### Why Random Feature Selection Works
**Intuition:** If an anomaly is truly anomalous, random features should isolate it regardless of which feature is chosen. Normal data requires specific feature combinations to be separated, so random choices make separation difficult (long paths).

This randomness is what makes Isolation Forest robust to feature correlations and high-dimensional data.

---

## 4. DistilBERT Transformer — Deep Algorithm Walkthrough

### Stage 1: WordPiece Tokenization
```
Input:  "http://paypal-secure.fakesite.tk/verify"
Tokens: ["http", ":", "//", "pay", "##pal", "-", "secure", ".", "fake", "##site", ".", "tk", "/", "verify"]
IDs:    [8299, 1024, 1013, 3477, 12344, 1011, 5765, 1012, 8275, 14585, 1012, 23927, 1013, 20410]
```

`##` prefix means the token is a continuation of the previous word (sub-word tokenization).

### Stage 2: Embedding Layer
Each token ID is converted to a 768-dimensional vector:

```
"pay"    → [0.23, -0.15, 0.87, 0.02, ..., -0.34]  (768 values)
"##pal"  → [0.45, 0.22, -0.13, 0.89, ..., 0.67]   (768 values)
"secure" → [-0.11, 0.56, 0.34, -0.78, ..., 0.12]  (768 values)
```

Position embeddings are added:
```
Position 0: [0.01, 0.02, 0.03, ...]
Position 1: [0.04, 0.05, 0.06, ...]
...
```

### Stage 3: Self-Attention (The Core Innovation)

**For each token, compute Query (Q), Key (K), and Value (V):**
```
Q_secure = W_q × embedding_secure    (768 → 64 per head, 12 heads)
K_secure = W_k × embedding_secure
V_secure = W_v × embedding_secure
```

**Compute attention scores between ALL token pairs:**
```
attention("secure", "pay")     = Q_secure · K_pay^T     =  0.21
attention("secure", "##pal")   = Q_secure · K_##pal^T   =  0.85  ← HIGH!
attention("secure", "fake")    = Q_secure · K_fake^T     =  0.73  ← HIGH!
attention("secure", "tk")      = Q_secure · K_tk^T       =  0.42
```

**Why this matters:** The word "secure" pays HIGH attention to "paypal" and "fake" — it learns that "secure" in context of a fake paypal domain is a phishing signal!

**Apply softmax to get attention weights:**
```
softmax([0.21, 0.85, 0.73, 0.42, ...]) = [0.05, 0.25, 0.22, 0.08, ...]
```

**Weighted sum of Values:**
```
output_secure = 0.05×V_pay + 0.25×V_##pal + 0.22×V_fake + 0.08×V_tk + ...
```

The output for "secure" now ENCODES information about its context (paypal, fake, tk).

### Stage 4: 6 Transformer Layers
This process repeats 6 times, with each layer building on the previous layer's output:
- Layer 1: Captures direct token-to-token relationships
- Layer 2: Captures indirect relationships (token A → token B → token C)
- Layer 3-4: Captures abstract semantic patterns
- Layer 5-6: Task-specific representations for classification

### Stage 5: [CLS] Token Classification
The `[CLS]` token (prepended to every input) collects information from all other tokens through self-attention. After 6 layers, its 768-dimensional representation encodes the "meaning" of the entire URL.

```
CLS_output (768 dims) → Dropout(0.4) → Linear(768 → 2) → Softmax → [P(benign), P(malicious)]
```

---

## 5. How Each Algorithm Works Stage-by-Stage in PhishShield

### Full Pipeline Execution Trace

**Input URL:** `http://paypal-login.secure-datalink.org/verify?id=a3f7b2c1-4d8e-9876-fedc-ba0123456789`

```
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 1: Global Blacklist Check                                      │
│ ├─ Check URL against in-memory blacklist                           │
│ ├─ Check domain "secure-datalink.org" against blacklist             │
│ └─ Result: NOT in blacklist → continue                              │
├─────────────────────────────────────────────────────────────────────┤
│ STEP 2: URL Feature Extraction (URLFeatureExtractor)               │
│ ├─ url_length = 78                                                  │
│ ├─ entropy_full_url = 4.63 (HIGH — random UUID in path)            │
│ ├─ has_brand_keyword = 1 ("paypal" detected)                       │
│ ├─ suspicious_tld = 0 (.org is not suspicious)                     │
│ ├─ has_ip_address = 0                                               │
│ ├─ is_https = 0 (HTTP only!)                                       │
│ └─ has_php = 0                                                      │
├─────────────────────────────────────────────────────────────────────┤
│ STEP 3: URL DistilBERT Prediction                                   │
│ ├─ Tokenize: ["http",":","//"..."verify","?","id","=","a","##3",...]│
│ ├─ Pad to 128 tokens                                                │
│ ├─ Forward pass through 6 transformer layers                        │
│ ├─ Softmax output: [0.15, 0.85]                                     │
│ └─ URL score = 0.85 (HIGH — DistilBERT detected phishing pattern)  │
├─────────────────────────────────────────────────────────────────────┤
│ STEP 4: Brand Impersonation Check                                   │
│ ├─ Extract registered domain: "secure-datalink.org"                 │
│ ├─ Brand keyword "paypal" found in URL                              │
│ ├─ Legitimate domain for paypal: "paypal.com"                       │
│ ├─ Match: "secure-datalink.org" ≠ "paypal.com" → IMPERSONATION     │
│ ├─ "paypal" in subdomain "paypal-login" → score = 0.90             │
│ ├─ UUID detected in path → score = max(0.90, 0.95) = 0.95         │
│ ├─ Credential keyword "login" + "verify" detected → score = 0.95   │
│ └─ Brand impersonation score = 0.95                                 │
├─────────────────────────────────────────────────────────────────────┤
│ STEP 5: INSTANT BLOCK (Pre-Liveness)                                │
│ ├─ brand_impersonation = 0.95 ≥ 0.70 → TRIGGER                    │
│ ├─ Return verdict: "malicious"                                      │
│ ├─ risk_score: 0.99                                                 │
│ ├─ confidence: 1.0                                                  │
│ ├─ latency: 4.2ms                                                   │
│ └─ stage_reached: "instant_url_block"                               │
└─────────────────────────────────────────────────────────────────────┘
```

**Total latency: 4.2ms** — The URL never reached the sandbox, content model, PHP analysis, or behavior model. The early-exit architecture saved ~8 seconds of compute.

### Alternative Trace: Subtle Phishing (Requires Deep Analysis)

**Input URL:** `https://sites.google.com/view/account-update-2024`

```
┌─────────────────────────────────────────────────────────────────────┐
│ STEP 1: Legitimate Brand Authentication                             │
│ ├─ Registered domain: "google.com"                                  │
│ ├─ google.com is in trusted_roots set                               │
│ └─ Result: LEGITIMATE BRAND → Return "safe" immediately            │
│   ├─ verdict: "safe"                                                │
│   ├─ risk_score: 0.0                                                │
│   ├─ confidence: 1.0                                                │
│   └─ latency: 1.1ms                                                │
└─────────────────────────────────────────────────────────────────────┘
```

**NOTE:** This is actually a LIMITATION — if a phishing page is hosted on a legitimate Google Sites domain, PhishShield's brand authentication will pre-emptively clear it. This is a conscious trade-off to prevent false positives on legitimate Google login pages. The alternative (scanning Google domains) would block millions of legitimate Google sessions daily.
