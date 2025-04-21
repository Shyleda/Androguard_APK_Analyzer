Static Analysis-Based Trojan Detection (Implemented)
To detect Android banking trojans, we implemented a static analysis script using the Androguard framework in Python. The tool analyzes APK files to identify potential malicious behaviors based on the following indicators:

Suspicious Permissions: Such as RECEIVE_SMS, BIND_ACCESSIBILITY_SERVICE, which are often abused by banking trojans to intercept OTPs or perform unauthorized UI interactions.

Dangerous API Calls: Including sendTextMessage(), getDeviceId(), and reflection (java.lang.reflect.Method), commonly used for sensitive data access or obfuscation.

Obfuscation Techniques: Detection of encrypted strings or reflection, which indicate attempts to hide malicious intent.
