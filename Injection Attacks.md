## Understanding Injection Attacks
Injection vulnerabilities occur when untrusted input is sent to an interpreter as part of a command or query. Attackers exploit this to trick the interpreter into executing unintended commands.

### Common Types of Injections:
- SQL Injection (SQLi)
- Command Injection
- LDAP Injection
- XML Injection
- Server-Side Template Injection (SSTI)
- NoSQL Injection

Each type targets a different backend component, but the root cause remains: **failure to validate and sanitize user input**.

### SQL Injection (SQLi)
SQLi targets database queries through unsanitized inputs. If inputs are interpolated directly into SQL queries, attackers can manipulate them.
```
' OR 1=1 --
admin' --
1'; DROP TABLE users; --
```
Tools for SQLi
- sqlmap (automated SQLi tool)
- Burp Suite
- SQLite3 CLI

### Command Injection
Occurs when input is injected into OS-level commands.
```
127.0.0.1; whoami
127.0.0.1 && id
127.0.0.1 || cat /etc/passwd
```
Tools for SQLi
- Netcat
- Burp Suite
- Gobuster for endpoint fuzzing

### Server-Side Template Injection (SSTI)
Template engines like Jinja2, Twig, and Handlebars may allow input to be interpreted as code.
```
{{7*7}}
{{config}}
{{ ''.__class__.__mro__[1].__subclasses__() }}
```
Tools for SQLi
- tplmap
- SSTImap
- Burp Repeater + Intruder

### NoSQL Injection
Targets NoSQL databases like MongoDB using JSON-style injection.

```{"username": {"$ne": null}, "password": {"$ne": null}}```
Tools for SQLi
- NoSQLMap
- MongoDB CLI
- Burp Suite
