#Password Strength Analyzer

A cyber security tool that evaluates password strength using:
- Entropy calculation
- Breach database checks via Have I Been pwned API
- Security recommendation
# Features
- Password strength analysis
- Breach occurrence checking
- Secure password generation
- JSON report export
- CLI and GUI interfaces!
# Installation
git clone https://github.com/yourusername/password-strength-tester

cd password-strength-tester

pip install -r requirements.txt
# Usage
## Command Line Interface
python src/cli_interface.py
## Graphical Interface
python src/gui_interface.py

# Security Considerations
**Important:** This tool processes passwords locally and:
- Never stores passwords
- Never transmits passwords over the network
- Masks passwords in reports
- Uses k-Anonymity for API queries
# Contributing
Pull requests welcome! Please follow OWASP security guidelines.
# License
MIT License
