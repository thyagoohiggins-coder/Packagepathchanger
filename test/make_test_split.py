# Usage: make_test_split.py out.apk split_name  -> config split of com.example.old
import sys, zipfile, os
from lxml import etree
from pyaxml import axml
A = "http://schemas.android.com/apk/res/android"
xml = f'''<manifest xmlns:android="{A}" package="com.example.old" split="{sys.argv[2]}" android:isFeatureSplit="false">
<application android:hasCode="false"/></manifest>'''
a = axml.AXML(); a.from_xml(etree.fromstring(xml.encode()))
with zipfile.ZipFile(sys.argv[1], 'w') as z:
    z.writestr('AndroidManifest.xml', a.pack(), zipfile.ZIP_DEFLATED)
    z.writestr('lib/arm64-v8a/liby.so', os.urandom(5000), zipfile.ZIP_STORED)
    z.writestr('META-INF/CERT.SF', 'x'); z.writestr('META-INF/CERT.RSA', 'x')
