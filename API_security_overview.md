# API Security Overview

## 🔐 What is API Security?
Protecting APIs from unauthorized access, misuse, or abuse.

Why important?
- APIs expose application logic & data
- Weak APIs become entry points for attackers

---

## 🚨 Common Weaknesses in APIs
- Lack of Authentication
- Broken Authentication (weak tokens, JWT issues)
- Excessive Data Exposure
- Lack of Rate Limiting
- Improper Authorization (Broken Access Control)
- Insecure Direct Object References (IDOR)
- Injection Attacks (SQL/NoSQL/Command)
- Unencrypted Communication (HTTP)
- Weak Logging & Monitoring

---

## 🛡️ What Hackers Can Do with Weak APIs
- Steal sensitive data (emails, health, finance)
- Hijack accounts (token replay, weak sessions)
- Privilege escalation (admin via IDOR)
- Mass scraping (spam, phishing)
- Fraud & manipulation (balances, transactions)
- Denial of Service (DoS via flooding)
- Lateral movement inside systems
- Exploit business logic flaws

---

## 🧑‍💻 Real-World Examples
- Facebook (2019): 419M phone numbers exposed
- T-Mobile (2021): 40M+ customer records stolen
- Parler (2021): 70TB of user data scraped due to no auth + IDOR

---

## ✅ Defense Strategies
- Strong authentication & authorization (OAuth2, JWT)
- Input validation & sanitization
- Rate limiting & throttling
- Least privilege – return only necessary data
- HTTPS everywhere
- Logging & monitoring
- Regular pentesting (OWASP API Top 10)

---

## 📚 Resources for Learning API Security
- [TryHackMe: OWASP API Security Top 10 - Part 1](https://tryhackme.com/room/owaspapisecurity1)
- [TryHackMe: OWASP API Security Top 10 - Part 2](https://tryhackme.com/room/owaspapisecurity2)
- [OWASP API Security Top 10 (official)](https://owasp.org/API-Security/)
- [PortSwigger Academy - API Testing](https://portswigger.net/web-security/api)

---

## 💡 Practical Exercises
- TryHackMe labs (API challenges with IDOR, broken auth, etc.)
- Use Burp Suite to test API endpoints for excessive data exposure
- Practice fuzzing APIs with tools like Postman, Insomnia, or curl
- Run OWASP ZAP scans against your own test APIs
