# AI-Based Phishing Detection and Explanation

This is the official GitHub repository for COMP_SCI-361's TonTru team.

## Project Overview

This project focuses on detecting phishing emails using an AI-based system while also providing clear, human-readable explanations for why an email is flagged. Unlike traditional black-box filters, this system improves both detection and transparency.

## Problem

Phishing remains one of the most common and effective cyber attacks. Many existing systems fail to detect advanced phishing attempts or provide no explanation for their decisions. This project addresses both detection accuracy and explainability.

## How the System Works

The system processes emails through five stages:

1. Input and sanitization
2. Feature extraction
3. Scoring
4. Explanation generation
5. Alert output

## Key Features

* Phishing vs legitimate email classification
* Explanation of detection signals
* Homograph (Unicode) URL detection
* Rate limiting to prevent probing attacks
* Secure configuration and audit logging

## Results

* Baseline performance: 60% pass rate
* With defensive controls: 70% pass rate
* Successfully fixed homograph attack detection (TC-05)
* Remaining challenges: spear phishing, digit-substitution domains, prompt injection scoring

## How to Run

```bash
python phishing_detection.py
```

## Tools Used

* Python
* VS Code
* tldextract
* colorama

## Team Members

* Muhammad Chaudhry — Project Lead / Risk Analyst
* Joshua Webber — Technical / Documentation Lead
* Yaseen Allan — QA / Research Support
* Sufyan Imran — System Architect / Evaluation Lead

## Repository Contents

* `phishing_detection.py` — main detection system
* `Final_Report.pdf` — complete project report
* `Final_Slides.pdf` — presentation slides
* `results.txt` — validation results

## Final Outcome

The project successfully demonstrates an AI-based phishing detection system that improves accuracy and adds explainability. While some advanced attack types remain unresolved, the system shows clear improvement over the baseline and provides a strong foundation for future enhancements.
