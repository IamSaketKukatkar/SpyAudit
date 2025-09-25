# Spy-Audit
**Real-Time Website Privacy & Threat Scanner**

[![Built With Flask](https://img.shields.io/badge/Built%20With-Flask-blue?style=flat-square)](https://flask.palletsprojects.com/)
[![Proxy Support](https://img.shields.io/badge/Proxy%20Support-Yes-green?style=flat-square)]()
[![AntiBot Header](https://img.shields.io/badge/AntiBot%20Header-Reversed%20Values-red?style=flat-square)]()

## Overview

A web security tool that performs real-time privacy and threat assessments of websites. Provides insights into trackers, fingerprinting attempts, and malware signals with a clean 0-100 privacy score.

**Key Features:**
- Real-time website scanning via VirusTotal (no API key required)
- Privacy scoring with threat classification (Safe/Caution/Unsafe)
- Stealth operation with residential proxy support
- Modern dark UI with responsive design

## Reverse Engineering Achievement

Successfully bypassed VirusTotal's anti-bot detection system by analyzing and inverting their client-side header mechanisms. This allows the scanner to operate without API keys while maintaining full accuracy and avoiding detection.

## Quick Start

```bash
git clone https://github.com/IamSaketKukatmar/Spy-Audit.git
cd Spy-Audit
pip install -r requirements.txt
python app.py
```

Visit `http://localhost:5000` to start scanning websites.

## Usage

1. Enter target website URL
2. Review privacy score and threat analysis
3. Interpret Safe/Caution/Unsafe verdict

## Contact

**Saket Kukatkar** - [@IamSaketKukatkar](https://github.com/saket-kukatkar)