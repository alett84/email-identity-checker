# Email Identity and Phishing Detection Tool 

## Overview
A python-based email analysis tool that inspects raw .eml files to detect impersonation and phishing attempts using identity-mismatch heuristics and rule-based scoring. 

## Features
- Parses raw .eml email files 
- Detects protected identity impersonation (e.g., CEO spoofing)
- Scores emails using weighted risk factors 
- Produces explainable verdicts (allow / warn / block)
- CLI-based analysis workflow 

## Technologies Used 
- Python
- Email MIME parsing 
- YAML configuration files 
- Command-line interface

## How it works 
- Loads a list of protected identities from a YAML configuration file 
- Extracts sender address and display name from email headers 
- Compares display names against protected identities 
- Flags mismatches where a trusted name is paired with an untrusted sender domain
- Assigns risk scores based on triggered rules and outputs a verdict 

## Example output 
Verdict: allow 
Score: 40 
Reason: Protected identity display name matched but sender domain was untrusted 

## Challenges and Lessons Learned 
- Learned how phising attacks exploit display name trust 
- Balanced false positives vs detection sensitivity 
- Gained experience parsing and analysing real email headers 

## Future Improvments 
- Domain reputation checks 
- SPF/DKIM/DMARC validation 
- Machine learning-based scoring 