"""
Phishing URL Detector
=======================
Detects malicious/phishing URLs using feature extraction
and machine learning classification.
"""

import pandas as pd
import numpy as np
import re
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

# ── 1. SAMPLE URLs ────────────────────────────────────────────────────────────

legitimate_urls = [
    'https://www.google.com/search?q=python',
    'https://github.com/user/repo',
    'https://www.amazon.in/products',
    'https://mail.google.com/mail/u/0/',
    'https://www.wikipedia.org/wiki/Machine_learning',
    'https://stackoverflow.com/questions/12345',
    'https://www.linkedin.com/in/username',
    'https://docs.python.org/3/library/',
    'https://www.flipkart.com/mobiles',
    'https://www.naukri.com/jobs',
    'https://medium.com/@author/article',
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://portal.azure.com/#home',
    'https://console.aws.amazon.com/',
    'https://www.coursera.org/learn/machine-learning',
]

phishing_urls = [
    'http://192.168.1.1/paypal-login/secure/update',
    'https://g00gle-security.com/verify-account',
    'http://paypai-secure-login.tk/account/confirm',
    'https://amazon-india-deals.xyz/claim-prize-now',
    'http://sbi-netbanking-secure.cf/login.php',
    'https://hdfc-bank-customer-support.ml/reset',
    'http://bit.ly/2xYqA9K-free-recharge-india',
    'https://facebook-login-securitycheck.gq/verify',
    'http://whatsapp-free-gift-prize.tk/claim',
    'https://income-tax-refund-gov-in.xyz/apply',
    'http://covid-relief-fund.tk/apply-now',
    'https://flipkart-lucky-draw-winner.cf/redeem',
    'http://update-your-kyc-sbi.ml/now',
    'https://jio-offer-free-data-limited.tk/get',
    'http://aadhaar-update-uidai-gov.cf/link',
]

# Generate more programmatically
np.random.seed(42)
def gen_legit():
    domains = ['google', 'amazon', 'microsoft', 'github', 'linkedin', 'twitter', 'youtube']
    tlds = ['.com', '.org', '.in', '.net', '.edu']
    paths = ['/login', '/account', '/products', '/search', '/home', '/about', '']
    return f"https://www.{np.random.choice(domains)}{np.random.choice(tlds)}{np.random.choice(paths)}"

def gen_phish():
    words = ['paypal', 'sbi', 'hdfc', 'amazon', 'google', 'facebook', 'income-tax', 'aadhaar']
    fakes = ['secure', 'login', 'verify', 'update', 'confirm', 'support', 'claim']
    tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq']
    protocols = ['http://', 'https://']
    ip = f"{np.random.randint(1,254)}.{np.random.randint(1,254)}.{np.random.randint(1,254)}.1"
    if np.random.random() < 0.3:
        return f"http://{ip}/{np.random.choice(words)}/login"
    return f"{np.random.choice(protocols)}{np.random.choice(words)}-{np.random.choice(fakes)}{np.random.choice(tlds)}/account"

extra_legit = [gen_legit() for _ in range(200)]
extra_phish = [gen_phish() for _ in range(200)]

all_urls = legitimate_urls + extra_legit + phishing_urls + extra_phish
all_labels = [0]*len(legitimate_urls) + [0]*len(extra_legit) + [1]*len(phishing_urls) + [1]*len(extra_phish)

df = pd.DataFrame({'url': all_urls, 'label': all_labels})
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# ── 2. FEATURE EXTRACTION ─────────────────────────────────────────────────────

def extract_features(url):
    features = {}

    # Basic length features
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_at_signs'] = url.count('@')
    features['num_question_marks'] = url.count('?')
    features['num_percent'] = url.count('%')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_uppercase'] = sum(c.isupper() for c in url)

    # Suspicious indicators
    features['has_ip'] = int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)))
    features['is_https'] = int(url.startswith('https'))
    features['has_at_sign'] = int('@' in url)
    features['has_double_slash'] = int('//' in url[7:])

    # TLD check
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.pw']
    features['suspicious_tld'] = int(any(url.endswith(t) or t + '/' in url for t in suspicious_tlds))

    # Suspicious keywords
    suspicious_kw = ['login', 'secure', 'verify', 'update', 'confirm', 'account',
                     'bank', 'prize', 'free', 'claim', 'winner', 'offer', 'kyc']
    url_lower = url.lower()
    features['suspicious_keywords'] = sum(kw in url_lower for kw in suspicious_kw)

    # Subdomain count
    try:
        domain = url.split('/')[2]
        features['subdomain_count'] = domain.count('.')
    except:
        features['subdomain_count'] = 0

    return features

print("Extracting features from URLs...")
features_list = [extract_features(url) for url in df['url']]
features_df = pd.DataFrame(features_list)

print(f"✅ Feature extraction complete: {features_df.shape}")

# ── 3. TRAIN MODEL ───────────────────────────────────────────────────────────

X = features_df
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2,
                                                      random_state=42, stratify=y)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\n🎯 Phishing Detection Accuracy: {accuracy*100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# ── 4. VISUALIZATIONS ────────────────────────────────────────────────────────

fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Phishing URL Detector Dashboard', fontsize=16, fontweight='bold')

# 4a. Phishing vs Legitimate pie
counts = df['label'].value_counts()
axes[0, 0].pie([counts[0], counts[1]], labels=['Legitimate', 'Phishing'],
               colors=['#4CAF50', '#F44336'], autopct='%1.1f%%', startangle=90)
axes[0, 0].set_title('Dataset Composition')

# 4b. Feature Importance
feat_imp = pd.DataFrame({'feature': X.columns,
                         'importance': model.feature_importances_}).sort_values('importance', ascending=False)
axes[0, 1].barh(feat_imp['feature'].head(10)[::-1], feat_imp['importance'].head(10)[::-1],
                color='#FF5722', alpha=0.85)
axes[0, 1].set_title('Top Features for Phishing Detection')
axes[0, 1].set_xlabel('Importance Score')

# 4c. Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Oranges', ax=axes[1, 0],
            xticklabels=['Legit', 'Phish'], yticklabels=['Legit', 'Phish'])
axes[1, 0].set_title(f'Confusion Matrix (Accuracy: {accuracy*100:.1f}%)')

# 4d. URL length distribution
for label, color, name in zip([0, 1], ['#4CAF50', '#F44336'], ['Legitimate', 'Phishing']):
    subset = features_df[df['label'] == label]['url_length']
    axes[1, 1].hist(subset, bins=30, alpha=0.6, color=color, label=name)
axes[1, 1].set_title('URL Length: Legitimate vs Phishing')
axes[1, 1].set_xlabel('URL Length (characters)')
axes[1, 1].set_ylabel('Count')
axes[1, 1].legend()

plt.tight_layout()
plt.savefig('phishing_dashboard.png', dpi=150, bbox_inches='tight')
print("\n✅ Dashboard saved as phishing_dashboard.png")
plt.show()

# ── 5. LIVE URL CHECKER ───────────────────────────────────────────────────────

print("\n" + "="*60)
print("🔍 PHISHING URL CHECKER")
print("="*60)
test_cases = [
    'https://www.google.com/search?q=python',
    'http://paypal-secure-login.tk/verify/account',
    'https://github.com/hackeringgirl/portfolio',
    'http://192.168.1.1/sbi/netbanking/login.php',
    'https://www.flipkart.com/mobile-phones',
]
for url in test_cases:
    feats = pd.DataFrame([extract_features(url)])
    pred = model.predict(feats)[0]
    prob = model.predict_proba(feats)[0][1]
    icon = "🚨 PHISHING" if pred == 1 else "✅ SAFE    "
    print(f"{icon} ({prob*100:.1f}% risk) → {url[:60]}")
