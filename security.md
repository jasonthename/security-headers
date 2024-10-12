## Static Code Security Scan Oct 11, 2024

> Remediated on Oct 11, 2024 @10:17PM - NOTE: URLs are parsed but Snyk still says that line app.py:135 is vulnerable.

$ bandit -r coding/security-headers
[main]  INFO    profile include tests: None
[main]  INFO    profile exclude tests: None
[main]  INFO    cli include tests: None
[main]  INFO    cli exclude tests: None
[main]  INFO    running on Python 3.11.9
Run started:2024-10-12 01:06:38.923354

Test results:
        No issues identified.

Code scanned:
        Total lines of code: 126
        Total lines skipped (#nosec): 0

Run metrics:
        Total issues (by severity):
                Undefined: 0
                Low: 0
                Medium: 0
                High: 0
        Total issues (by confidence):
                Undefined: 0
                Low: 0
                Medium: 0
                High: 0
Files skipped (0):
__________________________

$ snyk code test

Testing /home/analyst/coding/security-headers ...

 ✗ [Medium] Server-Side Request Forgery (SSRF)
   Path: app.py, line 115
   Info: Unsanitized input from an HTTP parameter flows into get, where it is used as an URL to perform a request. This may result in a Server Side Request Forgery vulnerability.


✔ Test completed

Organization:      jasonthename-nePMihEAJJf9KPM4ZSg9Ta
Test type:         Static code analysis
Project path:      /home/analyst/coding/security-headers

Summary:

  1 Code issues found
  1 [Medium]