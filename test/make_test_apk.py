import sys, zipfile, os, zlib
from lxml import etree
from pyaxml import axml
A = "http://schemas.android.com/apk/res/android"
xml = f'''<manifest xmlns:android="{A}" package="com.example.old" android:versionCode="1" android:versionName="1.0">
<uses-permission android:name="android.permission.INTERNET"/>
<permission android:name="com.example.old.permission.PRIV" android:protectionLevel="signature"/>
<uses-permission android:name="com.example.old.permission.PRIV"/>
<application android:name=".App" android:label="Test" android:taskAffinity="com.example.old">
<activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
<activity android:name="Other" android:parentActivityName=".MainActivity"/>
<activity android:name="com.lib.ThirdParty"/>
<service android:name="com.example.old.sub.Svc" android:process=":remote"/>
<provider android:name=".Prov" android:authorities="com.example.old.provider;com.example.old.other" android:exported="false"/>
</application></manifest>'''
a = axml.AXML(); a.from_xml(etree.fromstring(xml.encode()))
m = a.pack()
out = sys.argv[1]
with zipfile.ZipFile(out, 'w') as z:
    z.writestr('AndroidManifest.xml', m, zipfile.ZIP_DEFLATED)
    z.writestr('classes.dex', os.urandom(3_000_000), zipfile.ZIP_DEFLATED)
    z.writestr('resources.arsc', b'\x02\x00\x0c\x00' + os.urandom(5001), zipfile.ZIP_STORED)
    z.writestr('lib/arm64-v8a/libx.so', os.urandom(9000), zipfile.ZIP_STORED)
    z.writestr('assets/big.bin', b'A' * 2_500_000, zipfile.ZIP_DEFLATED)
    z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
    z.writestr('META-INF/CERT.SF', 'x'); z.writestr('META-INF/CERT.RSA', 'x')
    z.writestr('META-INF/services/foo', 'bar')
