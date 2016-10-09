# AntiCSRFBypass
Anti-CSRF Bypass is a simple Burp extension which helps you to update CSRF tokens in
requests sent by Burp tools. It does so by extracting a new and valid token from the
headers or body of a macro response and replacing the original token in the current
request.
