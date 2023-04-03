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

## Level 2

Opening in jadx shows a similar `MainActivity` launched on startup. This time,
the app loads a native library `libfoo.so`:

```java
    static {
        System.loadLibrary("foo");
    }
```

And defines two native functions:

```java
...
    private native void init();
...
    private native boolean bar(byte[] bArr);
...
```

Opening `libfoo.so` from the `lib` directory (using the arm64-v8a architecture),
the two native functions are defined by the functions
`Java_sg_vantagepoint_uncrackable2_MainActivity_init` and
`Java_sg_vantagepoint_uncrackable2_CodeCheck_bar`.

`onCreate` calls the native `init()` function to start. Opening the library in
Ghidra shows that it forks a new process and ptraces the parent process, as a
means of preventing another process from tracing it:


```c
ptrace(PTRACE_ATTACH,getppid(),0,0);
```

Meanwhile, the parent thread calls `waidpid` on the chid to allow it to finish.
The child sets a global variable at `0x011300c` to true and returns.

The rest of the code looks more or less identical, except that input is
validated against in the native `bar` function returning a sucess or failure
boolean.

```java
    public boolean a(String str) {
        return bar(str.getBytes());
    }
```

Reviewing this function in Ghidra shows a `strcmp` between the input string,
retrieved from two function calls that seem to resolve the `char[]` and `strlen`
of the string. Note this comparison only occurs if the global value, initialized
in `init`, is set to true:

```c
  if (initialized == true) {
    uStack72 = 0x74206c6c6120726f;
    local_50 = 0x6620736b6e616854;
    local_40 = 0x68736966206568;
    __s1 = (char *)(**(code **)(*param_1 + 0x5c0))(param_1,param_3,0); // assemble char*
    retval = (**(code **)(*param_1 + 0x558))(param_1,param_3); // strlen
    if ((retval == 0x17) && (retval = strncmp(__s1,(char *)&local_50,0x17), retval == 0)) {
      retval = 1;
    }
```

The decompilation is a bit obscure, however the disassembly shows that a qword
at 0x00100ea0 is loaded onto the stack, followed by 7 bytes (copied via word and
byte ops). 

```asm
00100dec 00 a9 c3 3d     ldr        q0,[x8, #offset s_Thanks_for_all_t_00100ea0]     = "Thanks for all t"
00100df0 08 ad 8c 52     mov        w8,#0x6568
00100df4 08 c4 ac 72     movk       w8,#0x6620, LSL #16
00100df8 29 6d 8e 52     mov        w9,#0x7369
00100dfc 0a 0d 80 52     mov        w10,#0x68
00100e00 ff 7f 00 a9     stp        xzr,xzr,[sp]=>local_50
00100e04 ff 0b 00 f9     str        xzr,[sp, #local_40]
00100e08 e0 03 80 3d     str        q0,[sp]=>local_50
00100e0c e8 13 00 b9     str        w8,[sp, #local_40]
00100e10 e9 2b 00 79     strh       w9,[sp, #local_40+0x4]
00100e14 ea 5b 00 39     strb       w10,[sp, #local_40+0x6]
```
Casting 0x00100ea0 to a `char[0x10]` shows the text `Thanks for all
t`, and the remaining string can be seen by reversing the tip when hovering over
the `local_40` stack variable:

![remaining string bytes](/images/remaining_string.png)

The assembled string is `Thanks for all the fish`, which is sucessful.

### Other Tips

Connect to an emulated device using `adb`:

```zsh
~/Library/Android/sdk/platform-tools/adb shell
```
