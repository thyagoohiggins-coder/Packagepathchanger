import sys, zipfile, struct, hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
apk, newpkg = sys.argv[1], sys.argv[2]
d = open(apk, 'rb').read()
# zip integrity + alignment
z = zipfile.ZipFile(apk); assert z.testzip() is None
names = z.namelist(); print(names)
assert not any(n.endswith(('.SF', '.RSA', 'MANIFEST.MF')) for n in names)
assert 'META-INF/services/foo' in names
for i in z.infolist():
    if i.compress_type == 0:
        off = i.header_offset + 30 + len(i.filename.encode()) + struct.unpack('<H', d[i.header_offset+28:i.header_offset+30])[0]
        al = 4096 if i.filename.endswith('.so') else 4
        assert off % al == 0, (i.filename, off)
# manifest
from pyaxml import axml
from lxml import etree
m = axml.AXML().from_axml(z.read('AndroidManifest.xml')) if False else None
import io
res = axml.AXML.__new__(axml.AXML)
x, _ = axml.AXML.from_axml(z.read('AndroidManifest.xml')) if isinstance(axml.AXML.from_axml(z.read('AndroidManifest.xml')), tuple) else (axml.AXML.from_axml(z.read('AndroidManifest.xml')), 0)
xml = etree.tostring(x.to_xml(), pretty_print=True).decode()
print(xml)
P = '{http://schemas.android.com/apk/res/android}'
root = etree.fromstring(xml.encode())
assert root.get('package') == newpkg
names = {e.get(P + 'name') for e in root.iter() if e.get(P + 'name')}
for n in [f'{"com.example.old"}.App', 'com.example.old.MainActivity', 'com.example.old.Other', 'com.lib.ThirdParty',
          'com.example.old.sub.Svc', 'com.example.old.Prov', newpkg + '.permission.PRIV']:
    assert n in names, n
provs = [e for e in root.iter('provider') if e.get(P + 'name')]
assert [e for e in root.iter('provider') if not e.get(P + 'name')][0].get(P + 'authorities') == 'com.thirdparty.auth'
prov = provs[0].get(P + 'authorities')
assert prov == f'{newpkg}.provider;{newpkg}.other', prov
p2 = provs[1]
assert p2.get(P + 'authorities') == f'{newpkg}.com.example.oldmail.provider', p2.get(P + 'authorities')
NP = f'{newpkg}.com.example.oldmail.permission.READ'
assert p2.get(P + 'readPermission') == NP
assert [e for e in root.iter('permission') if e.get(P + 'name') == NP][0].get(P + 'permissionGroup') == f'{newpkg}.com.example.oldmail.GROUP'
assert [e for e in root.iter('permission-group')][0].get(P + 'name') == f'{newpkg}.com.example.oldmail.GROUP'
ups = {e.get(P + 'name') for e in root.iter('uses-permission')}
assert NP in ups and 'com.other.permission.X' in ups and 'android.permission.INTERNET' in ups, ups
assert root.find('.//application').get(P + 'taskAffinity') == newpkg
assert [e for e in root.iter('activity')][1].get(P + 'parentActivityName') == 'com.example.old.MainActivity'
# v2 signature, independent verification
eocd = d.rfind(b'PK\x05\x06'); cdsize, cdoff = struct.unpack('<II', d[eocd+12:eocd+20])
assert d[cdoff-16:cdoff] == b'APK Sig Block 42'
bsz = struct.unpack('<Q', d[cdoff-24:cdoff-16])[0]; start = cdoff - bsz - 8
assert struct.unpack('<Q', d[start:start+8])[0] == bsz
pairs = d[start+8:cdoff-24]; p = 0; v2 = None
while p < len(pairs):
    l = struct.unpack('<Q', pairs[p:p+8])[0]; i = struct.unpack('<I', pairs[p+8:p+12])[0]
    if i == 0x7109871a: v2 = pairs[p+12:p+8+l]
    p += 8 + l
def lp(b, o=0):
    n = struct.unpack('<I', b[o:o+4])[0]; return b[o+4:o+4+n], o+4+n
signers, _ = lp(v2); signer, _ = lp(signers)
sd, o = lp(signer); sigs, o = lp(signer, o); pub, o = lp(signer, o)
sig_entry, _ = lp(sigs); algo = struct.unpack('<I', sig_entry[:4])[0]; sig, _ = lp(sig_entry, 4)
assert algo == 0x103
load_der_public_key(pub).verify(sig, sd, padding.PKCS1v15(), hashes.SHA256())
digs, o2 = lp(sd); certs, o2 = lp(sd, o2)
dent, _ = lp(digs); dd, _ = lp(dent, 4)
cert = x509.load_der_x509_certificate(lp(certs)[0]); assert cert.public_key().public_numbers() == load_der_public_key(pub).public_numbers()
# recompute digest; EOCD cd offset -> signing block start
sec1 = d[:start]; sec3 = d[cdoff:cdoff+cdsize]; sec4 = bytearray(d[eocd:]); sec4[16:20] = struct.pack('<I', start)
def chunks(b): return [b[i:i+1048576] for i in range(0, len(b), 1048576)]
cs = chunks(sec1) + chunks(sec3) + [bytes(sec4)]
ds = b''.join(hashlib.sha256(b'\xa5' + struct.pack('<I', len(c)) + c).digest() for c in cs)
top = hashlib.sha256(b'\x5a' + struct.pack('<I', len(cs)) + ds).digest()
assert top == dd, 'digest mismatch'
assert struct.unpack('<I', d[eocd+16:eocd+20])[0] == cdoff
print('ALL CHECKS PASSED')
