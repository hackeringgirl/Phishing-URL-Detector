# 🎣 Phishing URL Detector

A cybersecurity project that detects malicious phishing URLs using **feature engineering** and **machine learning** — no blacklists needed, just smart URL analysis.

## 📌 Project Overview

Phishing attacks trick users into visiting fake websites. This tool analyzes URL structure and content to flag suspicious links before you click them.

## 🧠 What I Built

- Collected and generated 430 URLs (legitimate + phishing)
- Extracted 16 features from each URL (length, dots, hyphens, IP presence, TLD type, etc.)
- Trained a **Random Forest Classifier** for detection
- Built a live URL checker that outputs risk percentage

## 🔑 Key Features Extracted from URLs

| Feature | Why It Matters |
|---------|----------------|
| `url_length` | Phishing URLs tend to be longer |
| `has_ip` | Using IP instead of domain name is suspicious |
| `suspicious_tld` | .tk, .ml, .cf domains are often used for phishing |
| `num_hyphens` | Many hyphens = fake brand (paypal-secure-login) |
| `suspicious_keywords` | Words like "verify", "confirm", "prize" |
| `is_https` | Legitimate sites usually use HTTPS |
| `num_dots` | Too many subdomains is suspicious |

## 📊 Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | ~92%+ |
| Algorithm | Random Forest |
| False Positive Rate | Very Low |

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python | Core language |
| Pandas & NumPy | Feature engineering |
| Scikit-learn | Model training & evaluation |
| Regex | URL pattern matching |
| Matplotlib & Seaborn | Visualization |

## 📁 Files

```
07-phishing-detector/
├── phishing_url_detector.py     # Main detection script
├── phishing_dashboard.png       # Visual output
└── README.md
```

## 🚀 How to Run

```bash
pip install pandas numpy matplotlib seaborn scikit-learn
python phishing_url_detector.py
```

## 🔍 Sample Output

```
✅ SAFE     (1.2% risk)  → https://www.google.com/search?q=python
🚨 PHISHING (96.8% risk) → http://paypal-secure-login.tk/verify/account
✅ SAFE     (3.4% risk)  → https://github.com/hackeringgirl/portfolio
🚨 PHISHING (94.1% risk) → http://192.168.1.1/sbi/netbanking/login.php
```

## 👩‍💻 Author

**hackeringgirl** — Built as part of my Data Analytics & Cybersecurity portfolio
