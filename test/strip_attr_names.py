# strip_attr_names.py in.apk out.apk            -> blanks attribute-name strings covered by the resource map
# strip_attr_names.py in.apk out.apk ref.apk    -> restores them from ref.apk (to decode the result with pyaxml)
import sys, struct, zipfile

def pool(d):
    size = struct.unpack('<I', d[12:16])[0]
    cnt, _, flags, ss = struct.unpack('<IIII', d[16:32])
    assert flags & 0x100 == 0
    offs = struct.unpack(f'<{cnt}I', d[36:36 + 4 * cnt])
    strs = []
    for o in offs:
        p = 8 + ss + o; n = struct.unpack('<H', d[p:p + 2])[0]
        strs.append(d[p + 2:p + 2 + 2 * n].decode('utf-16le'))
    rm = 8 + size
    assert struct.unpack('<H', d[rm:rm + 2])[0] == 0x180
    nmap = (struct.unpack('<I', d[rm + 4:rm + 8])[0] - 8) // 4
    ids = struct.unpack(f'<{nmap}I', d[rm + 8:rm + 8 + 4 * nmap])
    return strs, [i for i in range(nmap) if ids[i]], d[8 + size:]

def build(strs, rest):
    data = b''.join(struct.pack('<H', len(s)) + s.encode('utf-16le') + b'\0\0' for s in strs)
    data += b'\0' * ((4 - len(data) % 4) % 4)
    offs, o = [], 0
    for s in strs: offs.append(o); o += 4 + 2 * len(s)
    hdr = 28; size = hdr + 4 * len(strs) + len(data)
    p = struct.pack('<HHIIIIII', 1, hdr, size, len(strs), 0, 0, hdr + 4 * len(strs), 0)
    p += struct.pack(f'<{len(strs)}I', *offs) + data
    return struct.pack('<HHI', 3, 8, 8 + len(p) + len(rest)) + p + rest

src, dst = sys.argv[1], sys.argv[2]
zi = zipfile.ZipFile(src)
d = zi.read('AndroidManifest.xml')
strs, nmap, rest = pool(d)
if len(sys.argv) > 3:
    ref, _, _ = pool(zipfile.ZipFile(sys.argv[3]).read('AndroidManifest.xml'))
    for i in nmap: strs[i] = ref[i]
else:
    assert nmap
    for i in nmap: strs[i] = ''
with zipfile.ZipFile(dst, 'w') as zo:
    for i in zi.infolist():
        zo.writestr(i, build(strs, rest) if i.filename == 'AndroidManifest.xml' else zi.read(i))
