# \# 🔐 Hands-On Email Threat Analysis \& Detection System

# 

# 🚀 \*\*Cybersecurity Capstone Project | Email Forensics | Threat Intelligence | Automation\*\*

# 

# \---

# 

# \## 📌 Project Overview

# 

# This project demonstrates a \*\*real-world phishing investigation workflow\*\* using a suspicious `.eml` file. It combines:

# 

# \* 🔍 Email Forensics

# \* 🧠 Threat Intelligence Correlation

# \* 🤖 Automated Threat Scoring System

# 

# The goal: \*\*Detect, analyze, and classify phishing attacks with both manual and automated techniques.\*\*

# 

# \---

# 

# \## ⚠️ Key Findings

# 

# \* 🚨 Identified \*\*Confirmed Phishing Attack\*\*

# \* 🌍 Origin traced to \*\*botnet node (Bulgaria → Switzerland relay)\*\*

# \* 🎭 \*\*PayPal impersonation using typosquatting\*\*

# \* ☁️ Malicious payload hosted on \*\*Vercel cloud infrastructure\*\*

# \* 📊 Threat score: \*\*36/100 (Auto) → HIGH RISK (Manual override)\*\*

# 

# \---

# 

# \## 🧪 Methodology

# 

# \### 1. Environment Isolation

# 

# \* Kali Linux (VMware sandbox)

# \* No network execution for safety

# 

# \### 2. Email Header Analysis

# 

# \* SPF: ❌ Fail

# \* DKIM: ❌ Missing

# \* DMARC: ❌ Fail

# 

# \### 3. Content \& Social Engineering

# 

# \* Urgency + Fear tactics

# \* Fake PayPal invoice

# 

# \### 4. URL Analysis

# 

# \* Hidden phishing link via HTML anchor tag

# \* `paypalphish.vercel.app`

# 

# \### 5. Attachment Forensics

# 

# \* Fake `.docx` → ASCII text

# \* Payload: `"You got Hacked"`

# 

# \### 6. Threat Intelligence

# 

# \* VirusTotal → 17 vendors flagged malicious

# \* Abuse.ch + URLScan correlation

# 

# \---

# 

# \## 🤖 Automated Threat Scoring System

# 

# Built using:

# 

# \* Python

# \* Streamlit

# \* Plotly

# \* VirusTotal API

# 

# \### Scoring Parameters:

# 

# \* Attachments

# \* URLs

# \* Authentication failures

# \* Domain reputation

# \* Language analysis (AI)

# 

# \---

# 

# \## 📊 Features

# 

# ✅ Email header parsing

# ✅ URL extraction \& defanging

# ✅ Hash generation (MD5, SHA256)

# ✅ VirusTotal integration

# ✅ AI-assisted risk scoring

# ✅ Interactive dashboard

# 

# \---

# 

# \## 🛠️ Tech Stack

# 

# \* Python

# \* Streamlit

# \* Plotly

# \* Kali Linux

# \* VMware

# \* VirusTotal API

# \* OSINT Tools (Abuse.ch, URLScan)

# 

# \---

# 

# \## 📂 Project Structure

# 

# ```

# docs/        → Reports \& documentation  

# notebook/    → Threat scoring system  

# screenshots/ → Dashboard \& analysis proof  

# sample\_data/ → Test .eml file  

# ```

# 

# \---

# 

# \## 📸 Screenshots

# 

# (Add your dashboard + VirusTotal screenshots here)

# 

# \---

# 

# \## 🎯 What This Project Demonstrates

# 

# \* Real-world phishing investigation skills

# \* Threat intelligence correlation

# \* Secure malware handling

# \* Automation in cybersecurity

# \* SOC Analyst / Threat Analyst readiness

# 

# \---

# 

# \## 👨‍💻 Author

# 

# \*\*Mukul Kumar\*\*

# Cybersecurity Enthusiast | SOC Analyst Aspirant

# 

# \---

# 

# \## ⭐ If you like this project, give it a star!



