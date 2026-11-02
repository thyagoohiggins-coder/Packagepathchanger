#!/usr/bin/env bash
# Runs the core tests (no Android SDK needed). Requires: JDK 17, python3 with pyaxml lxml cryptography.
set -euo pipefail
cd "$(dirname "$0")/.."
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir -p "$W/cls"
javac -Xlint:none -d "$W/cls" app/src/main/java/com/pkgpatch/core/*.java test/Cli.java test/SplitCli.java
keytool -genkeypair -keystore "$W/k.p12" -storetype PKCS12 -storepass changeit -alias k -keyalg RSA \
  -dname CN=t -validity 365 >/dev/null 2>&1
NP=com.example.newpkg

echo "== APK simples"
python3 test/make_test_apk.py "$W/base.apk"
java -cp "$W/cls" Cli "$W/k.p12" "$W/base.apk" "$W/o.apk" $NP
python3 test/verify.py "$W/o.apk" $NP | tail -1

echo "== Bundle com splits"
python3 test/make_test_split.py "$W/s1.apk" config.arm64_v8a
python3 test/make_test_split.py "$W/s2.apk" config.pt
(cd "$W" && python3 -c "import zipfile;z=zipfile.ZipFile('b.apks','w');[z.write(f) for f in ['base.apk','s1.apk','s2.apk']]")
java -cp "$W/cls" SplitCli "$W/k.p12" "$W/b.apks" "$W/w" $NP | tail -1
python3 test/verify.py "$W/w/out/0.apk" $NP | tail -1

echo "== Manifesto com nomes de atributos removidos"
python3 test/strip_attr_names.py "$W/base.apk" "$W/strip.apk"
java -cp "$W/cls" Cli "$W/k.p12" "$W/strip.apk" "$W/o2.apk" $NP
python3 test/strip_attr_names.py "$W/o2.apk" "$W/o2r.apk" "$W/base.apk"
python3 - "$W/o2r.apk" $NP <<'PY'
import sys, zipfile
src = open('test/verify.py').read()
head = src.split('# zip integrity')[0]
body = src.split('# manifest')[1].split('# v2 signature')[0]
exec(head + "z = zipfile.ZipFile(apk)\n" + body.replace("print(xml)", ""))
print('STRIPPED MANIFEST CHECKS PASSED')
PY
echo "TODOS OS TESTES PASSARAM"
