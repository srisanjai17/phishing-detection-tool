# PhishGuard v3 
![Python](https://img.shields.io/badge/Python-3.10-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.2-lightgrey.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
## Demo Screenshot

Here’s how PhishGuard v3 looks in action:

![PhishGuard Screenshot](images/screenshot.png)



PhishGuard v3 is a machine learning–based phishing detection system built with **Random Forest** and deployed using a **Flask web application**.

##  Features
- Detects phishing URLs with high accuracy
- Random Forest classifier (Accuracy: 85.87%, ROC-AUC: 0.9377)
- Flask-based web interface for real-time link checks
- Balanced dataset of 11,430 URLs (legitimate vs phishing)

##  Project Structure
- `app.py` → Flask web app
- `train_model.py` → Model training script
- `feature_extractor.py` → URL feature extraction
- `realtime_scanner.py` → DNS, SSL, WHOIS, OpenPhish checks
- `templates/index.html` → Web interface
- `requirements.txt` → Dependencies
- `models/` → Saved Random Forest model

## 🔧 Installation
```bash
git clone https://github.com/srisanjai17/PhishGuard-v3.git
cd PhishGuard-v3
pip install -r requirements.txt
python train_model.py
python app.py
