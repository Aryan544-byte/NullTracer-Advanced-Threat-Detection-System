# SentinelForge – AI-Based Threat Detection System

## 🚀 Overview

SentinelForge is a real-time threat detection and monitoring system designed to identify suspicious system activities using behavioral analysis and rule-based detection. It provides a lightweight security layer for detecting unauthorized processes and anomalies in a Linux environment.

## 🎯 Features

* Real-time system monitoring
* Behavioral-based threat detection
* Whitelisting mechanism for trusted processes
* Logging and alerting system
* Modular architecture for future AI integration

## 🛠️ Tech Stack

* Python
* Linux (Ubuntu/Kali)
* System Monitoring (psutil)

## ⚙️ How It Works

* Continuously monitors running processes and system activities
* Compares processes against a predefined whitelist
* Detects anomalies such as unknown or suspicious processes
* Logs all activities and triggers alerts for potential threats

## 📂 Project Structure

sentinelforge/
│── main.py
│── monitor.py
│── detector.py
│── whitelist.txt
│── logs/

## ▶️ Usage

```bash
git clone https://github.com/yourusername/sentinelforge.git
cd sentinelforge
python3 main.py
```

## 🔮 Future Improvements

* AI/ML-based anomaly detection
* Integration with SIEM tools (Splunk/ELK)
* Dashboard for real-time visualization

## 📌 Use Case

* Endpoint monitoring
* Early-stage threat detection
* Security research and experimentation
