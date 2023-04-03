## Level 1

First, download and extract jadx on Linux. Then load the APK. The manifest shows
a single entry point with a MAIN action and LAUNCHER category:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="1" android:versionName="1.0" package="owasp.mstg.uncrackable1">
    <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="28"/>
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@mipmap/ic_launcher" android:allowBackup="true">
        <activity android:label="@string/app_name" android:name="sg.vantagepoint.uncrackable1.MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Navigating to the `MainActivity` in the source code shows an `onCreate` method
that might trip up certain emulators - the method performs three checks:

```java
/* loaded from: classes.dex */
public class c {
    public static boolean a() {
        for (String str : System.getenv("PATH").split(":")) {
            if (new File(str, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean b() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean c() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }
}
```

The first check, `a()`, validates that the system `PATH` does not contain `su`,
along with other checks,
meaning the process is run as a super user. This will occur on any Android
Studio Emulator that is NOT a Play Store version (noted as Android XX.X *Google
APIs* instead of Android XX.X *Google Play*). The result of running on a rooted
phone is an error popped in `onCreate`: 

![root device error](/images/root_emulation.png)

Choosing a Google Play version emulation will bypass this check, and the other
check (debug mode) does not pertain. At this point, passing the CrackMe requires
solving the logic in the `verify` method, which calls two obfuscated classes,
`a()` and `b()`:

```java
...
    public void verify(View view) {
        String str;
        String obj = ((EditText) findViewById(R.id.edit_text)).getText().toString();
        AlertDialog create = new AlertDialog.Builder(this).create();
        if (a.a(obj)) {
            create.setTitle("Success!");
            str = "This is the correct secret.";

...

/* loaded from: classes.dex */
public class a {
    public static boolean a(String str) {
        byte[] bArr;
        byte[] bArr2 = new byte[0];
        try {
            bArr = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
        } catch (Exception e) {
            Log.d("CodeCheck", "AES error:" + e.getMessage());
            bArr = bArr2;
        }
        return str.equals(new String(bArr));
    }

    public static byte[] b(String str) {
        int length = str.length();
        byte[] bArr = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return bArr;
    }
}
```

Quick analysis of `b()` shows that it unhexlifies a hex string into bytes.
Method `a()` calls another method (also called `a()`...) which creates an
AES-ECB cipher using the unhexlified string as its key. The cipher is
initialized with `opcode = 2`, which is equal to 
[Cipher.DECRYPT_MODE](https://developer.android.com/reference/javax/crypto/Cipher#DECRYPT_MODE)
, so it decrypts the base-64 decoded input string.

```java
/* loaded from: classes.dex */
public class a {
    public static byte[] a(byte[] bArr, byte[] bArr2) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES/ECB/PKCS7Padding");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(2, secretKeySpec);
        return cipher.doFinal(bArr2);
    }
}
```

To pass the verification check, the input must match the output of the
decryption operation. The simple
[UnCrackable-level1.py](/scripts/UnCrackable-level1.py) shows how to solve this
in Python. The output is a simple string: `I want to belive`. Inputting this
value shows a successful solve:

![solve of UnCrackable Level 1](/images/level1_solve.png)

### Other Tips

Connect to an emulated device using `adb`:

```zsh
~/Library/Android/sdk/platform-tools/adb shell
```
