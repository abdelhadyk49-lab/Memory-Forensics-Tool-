# Memory Forensics Tool

A graphical memory forensics analysis tool for Windows, Linux, and macOS images. Integrates Volatility with threat intelligence APIs for advanced analysis.

## Features

Run Commands: Select from a wide range of forensic plugins for different OS types.
Interactive Q&A and Help: Get instant answers to how to use the tool and perform investigations effectively.
Guided Workflow: Receive command suggestions based on your investigation type.
Threat Intelligence Integration: Lookup IPs using VirusTotal and analyze suspicious process names through MalwareBazaar.
YARA Malware Scanning: Automatically scan memory dump files using YARA rules to detect suspicious patterns, malware signatures, and indicators of compromise (IOCs).
Output Search & Highlight: Find and highlight specific artifacts or keywords within forensic analysis results.
Save Results: Automatically save command outputs and analysis results to the selected folder.

## Getting Started

### Prerequisites

- Python 3.8+
- Required Python packages:
  - `requests`
  - `tkinter` (standard in most Python installations)


This tool is intended for educational and lawful forensic purposes only.


This tool fully developed by Kareem Abdelhady.

LinkedIn: 
https://www.linkedin.com/in/kareem-abdelhady-a29b37355


********** IMPORTANT **********

Use your own API keys for VirusTotal and Malwarebazaar   ## they are free ##


VirusTotal API in lines 615 & 513

Malwarebazaar API in line 766 & 724

### INSTALL ###

1- Go to the Releases Page

2- Download the Latest ZIP File (Memory-Forensics-Tool-.zip)

3- Extract the ZIP File

4- Open the folder where you extracted the tool

5- In the folder window, type cmd in the address bar and press Enter
(This opens CMD directly in that directory)

6- Type  python import os.py

