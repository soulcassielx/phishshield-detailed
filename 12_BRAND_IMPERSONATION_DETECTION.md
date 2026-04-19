# SECTION 12: BRAND IMPERSONATION DETECTION — COMPLETE WORKFLOW

---

## TABLE OF CONTENTS
1. [What is Brand Impersonation?](#1-what-is-brand-impersonation)
2. [The Two-Layer Brand System: Authentication vs Impersonation](#2-two-layer-brand-system)
3. [Layer 1: Legitimate Brand Authentication — "Is This the REAL Website?"](#3-legitimate-brand-authentication)
4. [Layer 2: Brand Impersonation Scoring — "Is Someone FAKING This Brand?"](#4-brand-impersonation-scoring)
5. [How Does the ML Know This Is the Actual Website?](#5-how-ml-knows-actual-website)
6. [Scenario: User on a Malicious-Looking TLD But Completely Safe Cooking Site](#6-safe-cooking-site-scenario)
7. [Scenario: How Does PhishShield Handle New Legitimate Domains?](#7-new-legit-domains)
8. [Complete Decision Flow Diagram](#8-decision-flow)
9. [Edge Cases and How They're Handled](#9-edge-cases)
10. [Limitations and Honest Assessment](#10-limitations)

---

## 1. What is Brand Impersonation?

Brand impersonation is the #1 phishing technique worldwide. An attacker creates a URL that LOOKS like it belongs to a trusted brand but actually leads to a phishing page:

| Real Website | Phishing Impersonation |
|:---|:---|
| `https://www.paypal.com/login` | `https://paypal-login.secure-datalink.tk/verify` |
| `https://accounts.google.com` | `https://google-account-verify.xyz/signin` |
| `https://www.netflix.com/login` | `https://netflix.billing-update.ml/confirm` |

The phishing URL uses the brand name (paypal, google, netflix) but the ACTUAL DOMAIN is different (secure-datalink.tk, not paypal.com).

---

## 2. The Two-Layer Brand System: Authentication vs Impersonation

PhishShield has TWO separate brand-related checks that run BEFORE any ML model:

```
URL arrives
    │
    ▼
┌────────────────────────────────────┐
│ LAYER 1: Legitimate Brand Auth     │
│ "Is this the REAL paypal.com?"     │
│                                    │
│ IF registered_domain IS paypal.com │
│ → Return SAFE immediately (0ms)    │
│ → BYPASS all ML models             │
└──────────┬─────────────────────────┘
           │ NO (not the real domain)
           ▼
┌────────────────────────────────────┐
│ LAYER 2: Brand Impersonation Score │
│ "Is someone PRETENDING to be       │
│  paypal on a different domain?"    │
│                                    │
│ IF "paypal" in URL AND domain ≠    │
│    paypal.com → score = 0.75-0.95  │
│                                    │
│ IF score ≥ 0.70 → BLOCK instantly  │
└────────────────────────────────────┘
```

**These are OPPOSITE actions:**
- Layer 1: Brand keyword + matching domain → **ALLOW** (it's real)
- Layer 2: Brand keyword + NON-matching domain → **BLOCK** (it's fake)

---

## 3. Layer 1: Legitimate Brand Authentication — "Is This the REAL Website?"

### The Code (from `pipeline.py` line 537-561)

```python
def _is_legitimate_brand(self, url: str) -> bool:
    """Is this URL from the official domain of a protected brand?"""
    
    # Step 1: Extract the registered domain using tldextract
    ext = tldextract.extract(url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    #
    # Example: "https://accounts.google.com/signin"
    #   ext.subdomain = "accounts"
    #   ext.domain = "google"
    #   ext.suffix = "com"
    #   registered_domain = "google.com"
    
    # Step 2: Check against trusted brand domains
    trusted_roots = set(BRAND_DOMAINS.values()).union({
        "github.com", "yahoo.com", "openai.com", 
        "icloud.com", "dropbox.com", "trello.com"
    })
    # Total: 20 trusted domains
    
    # Step 3: Exact match only
    if registered_domain in trusted_roots:
        return True   # → Immediately return "safe" with confidence=1.0
    return False
```

### What This Means in Practice

| URL | registered_domain | In trusted_roots? | Action |
|:---|:---|:---|:---|
| `https://accounts.google.com/signin` | `google.com` | ✅ YES | **SAFE** — bypass all ML |
| `https://login.paypal.com/verify` | `paypal.com` | ✅ YES | **SAFE** — bypass all ML |
| `https://github.com/user/repo` | `github.com` | ✅ YES | **SAFE** — bypass all ML |
| `https://paypal-login.evil.tk/verify` | `evil.tk` | ❌ NO | Continue to brand impersonation check |
| `https://my-cooking-site.xyz/recipes` | `my-cooking-site.xyz` | ❌ NO | Continue to brand impersonation check |
| `https://mybank.com/login` | `mybank.com` | ❌ NO | Continue — "mybank" is NOT in the 14 brand list |

### How tldextract Works (The Domain Parser)

`tldextract` is a Python library that correctly parses even complex domains using the Mozilla Public Suffix List:

```python
# Simple domains:
tldextract.extract("https://www.google.com")
# → ExtractResult(subdomain='www', domain='google', suffix='com')

# Country-code TLDs:
tldextract.extract("https://www.bbc.co.uk")
# → ExtractResult(subdomain='www', domain='bbc', suffix='co.uk')
# registered_domain = "bbc.co.uk" (correct! not "co.uk")

# Free hosting subdomains:
tldextract.extract("https://mysite.github.io")
# → ExtractResult(subdomain='mysite', domain='github', suffix='io')
# registered_domain = "github.io"

# Deep subdomains:
tldextract.extract("https://mail.accounts.login.google.com/signin")
# → ExtractResult(subdomain='mail.accounts.login', domain='google', suffix='com')
# registered_domain = "google.com" (correct!)
```

This means even `login.paypal.com`, `accounts.live.microsoft.com`, and `id.apple.com` are correctly recognized as their parent brand.

---

## 4. Layer 2: Brand Impersonation Scoring — "Is Someone FAKING This Brand?"

### The Code (from `pipeline.py` line 580-639)

```python
def _brand_impersonation_score(self, url: str) -> float:
    url_lower = url.lower()
    
    # Step 1: Extract registered domain
    ext = tldextract.extract(url_lower)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    # Example: "paypal-login.evil.tk" → registered_domain = "evil.tk"
    
    # Step 2: Parse hostname + path
    hostname = parsed.hostname  # "paypal-login.evil.tk"
    path = parsed.path          # "/verify"
    full_url_text = hostname + path  # "paypal-login.evil.tk/verify"
    
    score = 0.0
    impersonated_brands = []
    
    # Step 3: For EACH of 14 protected brands:
    for brand, legit_domain in BRAND_DOMAINS.items():
        # Is the brand keyword in the URL?
        if brand in full_url_text:
            # Is the domain NOT the real brand domain?
            if registered_domain != legit_domain:
                # ★ IMPERSONATION DETECTED ★
                impersonated_brands.append(brand)
                score = max(score, 0.75)  # Base impersonation score
                
                # Aggravation: brand in SUBDOMAIN (classic phishing pattern)
                if brand in hostname.split(".")[0]:  # First subdomain segment
                    score = max(score, 0.90)
    
    # Step 4: Credential keyword amplification
    cred_count = sum(1 for kw in CREDENTIAL_KEYWORDS if kw in full_url_text)
    # CREDENTIAL_KEYWORDS = {"login", "signin", "verify", "confirm", "password", ...}
    
    if cred_count > 0 and impersonated_brands:
        score = max(score, 0.95)  # Brand + credential = almost certain phishing
    elif cred_count >= 2:
        score = max(score, 0.4)   # Multiple credentials without brand = suspicious
    
    # Step 5: UUID/hash detection (individualized phishing links)
    if impersonated_brands and UUID_REGEX_FOUND_IN_PATH:
        score = max(score, 0.95)
    
    return score
```

### Score Breakdown Table

| Condition | Score | Example |
|:---|:---|:---|
| Brand keyword in PATH only | 0.75 | `evil.tk/paypal/login` |
| Brand keyword in SUBDOMAIN | 0.90 | `paypal-login.evil.tk/verify` |
| Brand + credential keyword | 0.95 | `paypal-login.evil.tk/verify` (both "paypal" + "verify") |
| Brand + UUID in path | 0.95 | `paypal.evil.tk/a3f7b2c1-4d8e.../verify` |
| Multiple credential keywords only | 0.40 | `evil.tk/login-verify-account` (no brand) |
| No brand, no credentials | 0.00 | `cooking-recipes.xyz/pasta` |

### What Triggers Instant Block?

```python
if brand_impersonation >= 0.70 or scores.get("url", 0.0) >= 0.85:
    return ScanResult(verdict="malicious", risk_score=0.99)
```

This means ANY brand impersonation detection with score ≥ 0.75 triggers an **instant block** in <5ms — BEFORE even checking if the website is alive.

---

## 5. How Does the ML Know This Is the Actual Website?

### The Answer: It's NOT ML — It's Deterministic Domain Matching

**The ML models do NOT determine if a website is legitimate.** The legitimacy check is purely rule-based:

```
Step 1: Extract registered domain from URL (using tldextract + Mozilla Public Suffix List)
Step 2: Check if registered domain EXACTLY MATCHES a known brand domain
Step 3: If match → SAFE (bypass ML entirely)
        If no match + brand keyword present → IMPERSONATION (block)
        If no match + no brand keyword → CONTINUE to ML analysis
```

### Why This Works

The registered domain (e.g., `google.com`, `paypal.com`) is **immutable** — it's registered through ICANN-accredited registrars and cannot be faked:
- An attacker CANNOT create a website with the registered domain `google.com` (Google owns it)
- An attacker CAN create `google-login.evil.tk` — but the registered domain is `evil.tk`, not `google.com`
- `tldextract` correctly extracts `evil.tk` as the registered domain regardless of subdomains

### The Trust Chain
```
ICANN → Domain Registrar → Registered Domain Owner → Subdomains
│                                                          │
│  PhishShield trusts THIS level                           │
│  (google.com is owned by Google)                         │
│                                                          │
│  Attacker can only control THIS level                    │
│  (google-phish.evil.tk — subdomain of evil.tk)          │
```

### What the ML Models DO Contribute
The ML models handle URLs that are NOT brand impersonation:
- URLs with no brand keywords at all → ML classifies based on content/behavior
- Subtle phishing without popular brand names → ML catches via content analysis
- Novel attack patterns → Isolation Forest catches via anomaly detection

---

## 6. Scenario: User on a Malicious-Looking TLD But Completely Safe Cooking Site

### The Scenario
```
URL: https://grandma-recipes.xyz/delicious-pasta-sauce
TLD: .xyz (in SUSPICIOUS_TLDS set!)
Content: A legitimate recipe blog with no forms, no login, no brand mentions
```

### What Happens Step by Step

```
Step 1: Extract URL features
        ├─ suspicious_tld = 1 (.xyz is suspicious)
        ├─ has_brand_keyword = 0 (no brand names)
        ├─ entropy = 3.9 (normal)
        └─ is_https = 1

Step 2: Legitimate Brand Authentication
        ├─ registered_domain = "grandma-recipes.xyz"
        ├─ Is it in trusted_roots? NO
        └─ Continue to brand impersonation check

Step 3: Brand Impersonation Score
        ├─ Check "paypal" in URL? NO
        ├─ Check "google" in URL? NO
        ├─ Check all 14 brands? ALL NO
        ├─ Credential keywords? NO
        └─ brand_impersonation_score = 0.0 ✅ (no impersonation)

Step 4: URL Model Prediction
        ├─ DistilBERT processes "https://grandma-recipes.xyz/delicious-pasta-sauce"
        ├─ "grandma", "recipes", "delicious", "pasta", "sauce" → benign tokens
        └─ url_score = 0.15 (low risk)

Step 5: Structural Score
        ├─ suspicious_tld = 1 → +0.30
        ├─ All other features = 0
        └─ structural_score = 0.30

Step 6: Early Exit Check
        ├─ weighted_url = 0.15 * 0.12 + 0.30 * 0.10 = 0.018 + 0.030 = 0.048
        ├─ 0.048 < SAFE_THRESHOLD * 0.5 (0.075) → YES
        ├─ url_score 0.15 < 0.3 → YES
        ├─ brand_impersonation 0.0 < 0.3 → YES
        └─ ★ EARLY EXIT: Return "safe" with risk=0.048 ★

Result: SAFE ✅ — The .xyz TLD adds some structural risk (0.30) but the
        weighted score is so low that the URL exits early as safe.
        No sandbox, no content analysis, no deep scan needed.
        Latency: ~30ms
```

### Why the Suspicious TLD Didn't Kill It
- The `.xyz` TLD contributes only to `structural_score` (weight=0.10, just 10% of total)
- Without brand impersonation (weight contributes to structural too), the weighted total is 0.048
- The SAFE_THRESHOLD * 0.5 = 0.075 — so 0.048 passes comfortably
- The URL model helps too: "grandma-recipes-pasta-sauce" has very benign token patterns

### What If The Cooking Site HAD a Login Form?
```
URL: https://grandma-recipes.xyz/login
Content: Registration form with password field for recipe sharing
```

This would NOT early-exit (url_score might be higher due to "login"). The sandbox would render the page, and the content model would analyze it. However:
- Content model sees: `forms:1 password_fields:1 inputs:3 title:join grandma's recipes`
- No brand keywords → content risk is moderate (~0.35)
- Behavior model: normal loading, 1 form, no hidden elements → low risk (~0.10)
- **False-Positive Mitigation kicks in:**
  ```python
  if brand_score < 0.3 and pwd_fields == 0 and risk > 0.3:
      risk = risk * 0.45
  ```
  Wait — this site HAS password fields (pwd_fields=1), so FP mitigation doesn't apply.
  
  But the fused risk score is:
  ```
  risk = (0.15*0.12 + 0.35*0.30 + 0.10*0.28 + 0*0.20 + 0.30*0.10) / 1.0
       = (0.018 + 0.105 + 0.028 + 0 + 0.030) / 1.0
       = 0.181
  ```
  0.181 < 0.30 (safe threshold) → **verdict = "safe"** ✅

  The cooking site with a login form is STILL marked safe because:
  - No brand impersonation
  - Normal behavior
  - The total weighted risk is low enough

---

## 7. Scenario: How Does PhishShield Handle New Legitimate Domains?

### The Problem
When a new legitimate service launches (e.g., `https://newstartup.io/login`), PhishShield has never seen it. How does it decide if it's safe?

### The Answer: Multiple Layers of Defense Against False Positives

#### Layer A: No Brand Impersonation → No Instant Block
If the new domain doesn't use brand keywords from the 14-brand list, the brand impersonation score is 0.0. No instant blocking occurs.

#### Layer B: ML Models Analyze on Merit
The URL model and Content model evaluate the URL and content independently:
- If the new site has clean URL patterns → URL model returns low risk
- If the content looks normal (forms but no hidden elements, no external actions to suspicious domains) → Content model returns low risk

#### Layer C: Behavior Model is Brand-Agnostic
The Behavior Isolation Forest doesn't know or care about domains. It only measures:
- Are the redirect patterns normal?
- Are the XHR counts normal?
- Is the page load time normal?

A new legitimate site with normal behavior → low anomaly score.

#### Layer D: False-Positive Mitigation
If the new site has NO brand impersonation AND NO password fields:
```python
if brand_score < 0.3 and pwd_fields == 0 and risk > 0.3:
    risk = risk * 0.45  # Discount risk by 55%
```

Even if ML models are slightly confused by a new domain, this mitigation keeps the risk below blocking threshold.

#### Layer E: Crowdsourced Whitelist
If a new legitimate site IS falsely blocked, users can report it:
```
POST /report {"url": "https://newstartup.io", "type": "safe"}
```
This adds the domain to the whitelist → all future scans return safe instantly.

### What If a New LEGITIMATE Site Uses a Brand Name?
Example: A company called "Apple Orchards Farm" launches `https://appleorchards.farm/shop`

```
Step 1: registered_domain = "appleorchards.farm"
Step 2: "appleorchards.farm" NOT in trusted_roots → continue
Step 3: Brand check: "apple" IS in "appleorchards.farm"
        → registered_domain "appleorchards.farm" ≠ "apple.com"
        → brand_impersonation_score = 0.75 ❌ FALSE POSITIVE!
Step 4: 0.75 ≥ 0.70 → INSTANT BLOCK! ❌

Result: FALSE POSITIVE — legitimate business blocked because name contains "apple"
```

**This is a KNOWN LIMITATION.** The brand detection uses naive substring matching. "apple" in "appleorchards" triggers a false positive.

### Mitigations for This Limitation
1. **User reports:** The orchard can report via `/report` endpoint → whitelisted
2. **Future improvement:** Use word-boundary matching (`\bapple\b` instead of `apple`) to avoid matching substrings
3. **Future improvement:** Context-aware brand matching (check if surrounding words reduce brand intent)

---

## 8. Complete Decision Flow Diagram

```
                        URL Input
                            │
                    ┌───────▼───────┐
                    │ Global Lists  │
                    │ Blacklist?    │──YES──→ MALICIOUS (0ms)
                    │ Whitelist?    │──YES──→ SAFE (0ms)
                    └───────┬───────┘
                            │ NOT IN LISTS
                    ┌───────▼───────────────┐
                    │ Extract Features       │
                    │ tldextract → domain    │
                    │ URL features (25+)     │
                    └───────┬───────────────┘
                            │
                    ┌───────▼───────────────┐
             ┌──YES─┤ is_legitimate_brand?  │
             │      │ domain ∈ trusted_roots│
             │      └───────┬───────────────┘
             │              │ NO
             ▼              │
      ┌──────────┐  ┌──────▼───────────────┐
      │ SAFE     │  │ brand_impersonation  │
      │ risk=0.0 │  │ score calculation     │
      │ conf=1.0 │  │                       │
      │ <2ms     │  │ Check 14 brand names  │
      └──────────┘  │ + credential keywords │
                    │ + UUID detection       │
                    └──────┬───────────────┘
                           │
                    ┌──────▼───────────────┐
             ┌──YES─┤ score ≥ 0.70?        │
             │      │ OR url_score ≥ 0.85? │
             │      └──────┬───────────────┘
             │             │ NO
             ▼             │
      ┌──────────┐  ┌─────▼────────────────┐
      │ BLOCKED  │  │ Continue to ML       │
      │ risk=0.99│  │ analysis pipeline    │
      │ <5ms     │  │ (URL, Content,       │
      └──────────┘  │  Behavior, PHP,      │
                    │  Zero-Day models)     │
                    └──────┬───────────────┘
                           │
                    ┌──────▼───────────────┐
                    │ FP Mitigation        │
                    │ IF no brand spoof    │
                    │ AND no password      │
                    │ → risk *= 0.45       │
                    └──────┬───────────────┘
                           │
                    ┌──────▼───────────────┐
                    │ Final Verdict         │
                    │ risk > 0.58 → MAL    │
                    │ risk > 0.30 → SUSP   │
                    │ risk ≤ 0.30 → SAFE   │
                    └──────────────────────┘
```

---

## 9. Edge Cases and How They're Handled

| Edge Case | What Happens | Result |
|:---|:---|:---|
| `login.paypal.com` (real PayPal) | tldextract → `paypal.com` → in trusted_roots | ✅ SAFE (bypass ML) |
| `paypal.evil.tk` (fake PayPal) | tldextract → `evil.tk` + "paypal" found → impersonation=0.90 | 🔴 BLOCKED |
| `paypal.com.evil.tk` (sneaky fake) | tldextract → `evil.tk` + "paypal" found → impersonation=0.75 | 🔴 BLOCKED |
| `my-paypal-shop.com` (legit business?) | tldextract → `my-paypal-shop.com` + "paypal" → impersonation=0.75 | 🔴 BLOCKED (false positive!) |
| `cooking-recipes.xyz` (safe, suspicious TLD) | No brand → impersonation=0.0, URL model=low risk | ✅ SAFE |
| `totally-new-service.com/login` | No brand → impersonation=0.0, ML analyzes content | ✅ SAFE (if content is normal) |
| `sites.google.com/phishing-page` | tldextract → `google.com` → in trusted_roots | ⚠️ SAFE (false NEGATIVE! Phishing on Google) |
| `bit.ly/3xK9mN2` (shortened URL) | `has_shortener_pattern=1` → structural risk +0.15 | Analyzed normally by ML |

---

## 10. Limitations and Honest Assessment

### Limitation 1: Substring Matching Causes False Positives
- "apple" in "pineapple-recipes.com" → triggers impersonation
- "chase" in "purchaser.com" → triggers impersonation
- **Fix needed:** Word-boundary regex (`\bapple\b`) or context awareness

### Limitation 2: Only 14 Brands Protected
- PhishShield only checks 14 specific brands
- Phishing targeting DHL, FedEx, Walmart, Target, etc. is NOT detected by brand impersonation
- These URLs go through normal ML analysis (which may still catch them)

### Limitation 3: Legitimate Domain Bypass is Exploitable
- `sites.google.com`, `github.io`, `vercel.app` are all whitelisted
- Phishing hosted on these domains bypasses ALL ML models
- This is a conscious trade-off: blocking real Google logins would be worse than missing Google-hosted phishing

### Limitation 4: No International Brand Support
- Only English brand names are checked
- Local bank names (e.g., "Sparkasse" in Germany, "SBI" in India) are not in the list

### Limitation 5: Static Brand List
- New brands must be manually added to `BRAND_DOMAINS` dictionary
- No automatic brand discovery or learning from user data
