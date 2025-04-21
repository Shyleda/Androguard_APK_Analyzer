from androguard.misc import AnalyzeAPK

# List of suspicious permissions commonly used by banking trojans
suspicious_permissions = {
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.INTERNET",
    "android.permission.GET_ACCOUNTS"
}

# List of suspicious APIs or methods
suspicious_apis = [
    "sendTextMessage", "getDeviceId", "getSubscriberId",
    "getInstalledPackages", "startActivity", "exec",
    "java.lang.reflect.Method", "loadClass"
]

def detect_apk_trojan(apk_path):
    a, d, dx = AnalyzeAPK(apk_path)

    print(f"\n[+] App: {a.get_app_name()}")
    print(f"[+] Package: {a.get_package()}")

    # 1. Permission check
    app_perms = set(a.get_permissions())
    flagged_perms = app_perms & suspicious_permissions
    print("\n[!] Suspicious Permissions:")
    for perm in flagged_perms:
        print(f"  - {perm}")

    # 2. API usage check
    print("\n[!] Suspicious API Calls:")
    for method in dx.get_methods():
        for suspicious in suspicious_apis:
            if suspicious in method.name:
                print(f"  - {method.class_name}->{method.name}")

    # 3. Reflection/Obfuscation signs
    print("\n[!] Obfuscation Indicators:")
    for method in dx.get_methods():
        if "java/lang/reflect/Method" in method.class_name:
            print(f"  - Reflective call in: {method.name}")
        if "base64" in method.name.lower():
            print(f"  - Potential encoding: {method.name}")

    print("\n✅ Analysis Complete\n")

# Example usage
apk_file = "1719125784_VLC-Android-1.9.0-ARMv7.apk"
detect_apk_trojan(apk_file)
