# 🛡️ Understanding Injection Attacks

Injection vulnerabilities are one of the **most dangerous categories in web security**. They occur when **untrusted input** is sent to an interpreter (SQL engine, OS shell, LDAP, XML parser, template engine, etc.) as part of a command or query.  

If input isn’t properly **validated and sanitized**, attackers can **alter queries, execute arbitrary commands, or exfiltrate sensitive data**.  
💡 Injection flaws are consistently ranked in the **[OWASP Top 10](https://owasp.org/Top10/)**.


## 🔑 Common Types of Injection Attacks
- **SQL Injection (SQLi)**
- **Command Injection**
- **LDAP Injection**
- **XML Injection (XXE)**
- **Server-Side Template Injection (SSTI)**
- **NoSQL Injection**

Each type targets different backend components, but the **root cause remains the same**:  
➡️ Lack of proper **input validation & sanitization**.

---

## SQL Injection (SQLi)

SQL Injection occurs when attackers manipulate database queries via **unsanitized inputs**.  

### Attack Payloads
```sql
' OR 1=1 --
admin' --
1'; DROP TABLE users; --
```
### Tools
- sqlmap (automated exploitation)
- Burp Suite (manual testing)
- SQLite3 / MySQL CLI (query validation)

---

# Command Injection

**Command Injection** occurs when user input is passed directly into system commands.


## Attack Payloads
```127.0.0.1; whoami
127.0.0.1 && id
127.0.0.1 || cat /etc/passwd
```

## ⚡ Impact
- Execute arbitrary OS commands  
- Read sensitive files (`/etc/passwd`, API keys)  
- Pivot into reverse shells  
## 🛠 Tools
- **Netcat** → exfiltration / reverse shell  
- **Burp Suite Repeater** → payload injection  
- **Gobuster** → endpoint discovery for injection points  
---

# LDAP Injection

**LDAP Injection** occurs when unsanitized input is used to build LDAP queries for directory services (e.g., Active Directory, OpenLDAP).

## 💣 Attack Payloads

`*)(uid=*))(|(uid=*`

## ⚡ Impact
- Authentication bypass  
- Extract sensitive directory data (users, groups, emails)  
- Modify or delete directory entries  
## 🛠 Tools
- **ldapsearch CLI**  
- **Burp Suite** (payload fuzzing)  
- **Custom Python scripts** with `ldap3`  
---

# XML External Entity (XXE) Injection

**XXE (XML External Entity Injection)** happens when XML parsers process **user-controlled input** that includes malicious entities.

## 💣 Attack Payloads
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>
  <data>&xxe;</data>
</root>
```
## ⚡ Impact
- Read local files  
- SSRF (Server-Side Request Forgery) via external DTDs  
- Denial of Service (**Billion Laughs Attack**)  
## 🛠 Tools
- **Burp Suite** → manual XML payload injection  
- **XXE payload libraries** → [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)  
---

# Server-Side Template Injection (SSTI)

**SSTI** abuses template engines (e.g., **Jinja2**, **Twig**, **Handlebars**, etc.) that render **user-supplied input** without proper sanitization.  
Attackers can inject malicious template expressions that get executed on the server.

## 💣 Attack Payloads
```jinja
{{7*7}}                → 49
{{"".__class__.__mro__[1].__subclasses__()}}
```
## ⚡ Impact
- Sensitive data exposure  
- Remote Code Execution (RCE)  
- Lateral movement inside application servers  
## 🛠 Tools
- **tplmap** → automated SSTI exploitation  
- **SSTImap** → advanced payload testing  
- **Burp Suite (Repeater + Intruder)** → payload fuzzing  
---

# NoSQL Injection

**NoSQL Injection** targets non-relational databases (e.g., **MongoDB**, **CouchDB**), where user inputs are interpreted inside JSON-like queries without proper validation.  
Attackers exploit weak query building to manipulate or bypass database operations.

## 💣 Attack Payloads
```json
{ "username": { "$ne": null }, "password": { "$ne": null } }
```

## ⚡ Impact
- Authentication bypass  
- Query manipulation  
- Full database dump  
## 🛠 Tools
- **NoSQLMap** → automated NoSQL injection exploitation  
- **MongoDB CLI** → manual queries & testing  
- **Burp Suite** → payload fuzzing and injection  
