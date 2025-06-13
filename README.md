# Squatter Scan

![screenshot](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![screenshot](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)

Squatter Scan is an advanced **domain squatting and typo-squatting detection tool** built for cybersecurity professionals, red teamers, and threat hunters. It takes in a list of domains and outputs typosquatted variations, checks if they are registered, evaluates their infrastructure, and flags potential threats—**all with a single command**.

> 🛡️ Provide real value without the noise. Squatter Scan aims to be fast, practical, and informative—while skipping over false positives.

---

## 🚀 Features

- 🔠 Generates dozens of typo-variations for each input domain
- 🌐 Checks DNS resolution and IP address
- 🔐 Verifies if SSL is present
- ☁️ Flags domains hosted in **cloud infrastructure** (AWS, GCP, Azure, etc.)
- 📅 Displays **creation date** and flags **newly registered** domains
- 📄 Optional CSV export for reporting
- ⚡ Asynchronous, fast, and clean CLI output with Rich

![screenshot](https://i.imgur.com/kMJF8FW.png)

---

## 🛠️ Installation

```bash
git clone https://github.com/yourusername/squatter_scan.git
cd squatter_scan
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📥 Usage
```bash
python3 squatter_scan.py --domains domains.txt
```

---

## 🙌 Contributing

Pull requests are welcome! Please open an issue first to discuss your ideas or improvements.
