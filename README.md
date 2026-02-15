# Email Identity and Phishing Detection Tool 
A python-based email analysis tool that inspects raw .eml files to detect impersonation and phishing attempts using identity-mismatch heuristics and rule-based scoring. 

## Overview
This email identity checker is a lightweight email analysis tool that evaluates '.eml' files against configurable identity protection rules. It detects: 
    - Display name spoofing 
    - Protected identity mismatches 
    - Requests for personally identifiable information (SSN, credit card number, etc.)

The system generates a verdict (allow, flag, quarantine) along with a confidence score and detailed reasoning for transparency. This project simulates real-world email security mechanisms used in secure mail gateways and phishing detection systems. 

## Problem Statement 
Buisness email compramises and impersonation attacks often rely on: 
Matching a trusted employee's display name 
Using an external email domain 
Social engineering tactics to bypass human review 
Traditional spam filters may miss these attacks because the content itself is not malicious. This tool focuses specifically on identity-based protection, not content scanning, making it effective against social engineering-based phishing attempts. 

## Technical Architecture
Content Extraction Layer 
    Parses '.eml' files 
    Extracts sender name, email address, subject, and body 
Rule Engine 
    Each rule recieves:
        ctx: dict
        cfg: dict
    Rules return: 
        Score impact
        Reason code
        Explination
Scoring Engine 
    Aggregates rule scores 
    Determines final verdict 
Configuration Layer 
    YAML-based identity configuration
    Supports protected identities and allowed domains 

## Example Rule: Sensitive Information Requests 
Detects when body contains: 
    Social security 
    SSN
    Routing Number 
    Direct Deposit
    And more 
Example output: 
    Verdict: tag
    Score: 40

    Reasons:
     PROTECTED_IDENTITY_MISMATCH: +40 (Display name matches protected identity "Henry Fonda (CEO)" but sender address "randomphisher@gmail.com" is not allowed.)

## Technologies Used 
Python 3
YAML Configuration
CLI-based interface 
Modular rule architecture 

## Design Goals 
Modular and extensible rule system 
Transparent reasoning for each verdict 
Easy configuration of protected identities 
Lightweight and dependency minimal 

## Security Concepts Demonstrated 
Business Email Compramise 
Identity Spoofing 
Domain-based trust modeling 
Rule-based detection vs content filtering 
Risk scoring systems 

## Future Improvments 

## Why does this project matter? 
This project demonstrates: 
    Understanding of email security threats 
    Defensive security mindset
    Modular backedn architecture 
    Real-world security tooling design 
    Clean SLI interface design 
It also reflects practical knowledge relevant to: 
Email Security engineering 
SOC tooling 
Secure system design 
Threat detection engineering 