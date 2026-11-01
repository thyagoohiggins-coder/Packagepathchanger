package com.pkgpatch.core;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Edits a binary AndroidManifest.xml to change the package name. */
public final class AxmlPatcher {
    private static final int XML_FILE = 0x0003, POOL = 0x0001, START_ELEM = 0x0102;
    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";
    private static final Set<String> CLASS_ELEMS = new HashSet<>(Arrays.asList(
            "application", "activity", "activity-alias", "service", "receiver", "provider", "instrumentation"));
    private static final Set<String> CLASS_ATTRS = new HashSet<>(Arrays.asList(
            "targetActivity", "backupAgent", "manageSpaceActivity", "parentActivityName"));
    private static final Set<String> PERM_ELEMS = new HashSet<>(Arrays.asList(
            "permission", "permission-group", "permission-tree", "uses-permission", "uses-permission-sdk-23"));
    private static final Set<String> PREFIX_ATTRS = new HashSet<>(Arrays.asList(
            "permission", "readPermission", "writePermission", "taskAffinity", "process"));

    private final byte[] src;
    private boolean utf8;
    private int poolEnd;
    private final List<String> strings = new ArrayList<>();
    private final List<byte[]> raw = new ArrayList<>();

    private AxmlPatcher(byte[] src) { this.src = src; parsePool(); }

    private ByteBuffer bb(byte[] b) { return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN); }

    private void parsePool() {
        ByteBuffer b = bb(src);
        if ((b.getShort(0) & 0xFFFF) != XML_FILE) throw new IllegalArgumentException("Not a binary XML");
        int off = 8;
        if ((b.getShort(off) & 0xFFFF) != POOL) throw new IllegalArgumentException("String pool not first");
        int hdr = b.getShort(off + 2) & 0xFFFF, size = b.getInt(off + 4);
        int count = b.getInt(off + 8), styles = b.getInt(off + 12), flags = b.getInt(off + 16);
        int strStart = b.getInt(off + 20);
        if (styles != 0) throw new IllegalArgumentException("Styled string pool unsupported");
        utf8 = (flags & 0x100) != 0;
        for (int i = 0; i < count; i++) {
            int p = off + strStart + b.getInt(off + hdr + 4 * i);
            int start = p, len;
            String s;
            if (utf8) {
                int[] r = u8len(p); p += r[1];
                r = u8len(p); p += r[1];
                len = r[0];
                s = new String(src, p, len, StandardCharsets.UTF_8);
                p += len + 1;
            } else {
                int n = b.getShort(p) & 0xFFFF; p += 2;
                if ((n & 0x8000) != 0) { n = ((n & 0x7FFF) << 16) | (b.getShort(p) & 0xFFFF); p += 2; }
                s = new String(src, p, n * 2, StandardCharsets.UTF_16LE);
                p += n * 2 + 2;
            }
            strings.add(s);
            raw.add(Arrays.copyOfRange(src, start, p));
        }
        poolEnd = off + size;
    }

    private int[] u8len(int p) {
        int v = src[p] & 0xFF;
        if ((v & 0x80) != 0) return new int[]{((v & 0x7F) << 8) | (src[p + 1] & 0xFF), 2};
        return new int[]{v, 1};
    }

    private byte[] encode(String s) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (utf8) {
            byte[] d = s.getBytes(StandardCharsets.UTF_8);
            wl8(o, s.codePointCount(0, s.length()));
            wl8(o, d.length);
            o.write(d, 0, d.length); o.write(0);
        } else {
            byte[] d = s.getBytes(StandardCharsets.UTF_16LE);
            int n = s.length();
            if (n > 0x7FFF) { int h = (n >> 16) | 0x8000; o.write(h & 0xFF); o.write(h >> 8); o.write(n & 0xFF); o.write((n >> 8) & 0xFF); }
            else { o.write(n & 0xFF); o.write(n >> 8); }
            o.write(d, 0, d.length); o.write(0); o.write(0);
        }
        return o.toByteArray();
    }

    private static void wl8(ByteArrayOutputStream o, int n) {
        if (n > 0x7F) { o.write((n >> 8) | 0x80); o.write(n & 0xFF); } else o.write(n);
    }

    private interface AttrVisitor { void visit(String elem, int ns, String attr, int attrPos, ByteBuffer b); }

    private void walk(byte[] data, int from, AttrVisitor v) {
        ByteBuffer b = bb(data);
        int p = from;
        while (p + 8 <= data.length) {
            int type = b.getShort(p) & 0xFFFF, size = b.getInt(p + 4);
            if (size <= 0) break;
            if (type == START_ELEM) {
                String elem = strings.get(b.getInt(p + 20));
                int attrStart = b.getShort(p + 24) & 0xFFFF, attrSize = b.getShort(p + 26) & 0xFFFF;
                int cnt = b.getShort(p + 28) & 0xFFFF;
                for (int i = 0; i < cnt; i++) {
                    int ap = p + 16 + attrStart + i * attrSize;
                    v.visit(elem, b.getInt(ap), strings.get(b.getInt(ap + 4)), ap, b);
                }
            }
            p += size;
        }
    }

    private String nsOf(int idx) { return idx < 0 ? null : strings.get(idx); }

    /** Returns the package declared in the manifest. */
    public static String readPackage(byte[] axml) {
        AxmlPatcher a = new AxmlPatcher(axml);
        byte[] rest = Arrays.copyOfRange(axml, a.poolEnd, axml.length);
        String[] out = new String[1];
        a.walk(rest, 0, (elem, ns, attr, ap, b) -> {
            if (out[0] == null && elem.equals("manifest") && ns == -1 && attr.equals("package"))
                out[0] = a.valueAt(ap, b);
        });
        if (out[0] == null) throw new IllegalArgumentException("package attribute not found");
        return out[0];
    }

    private String valueAt(int ap, ByteBuffer b) {
        int raw = b.getInt(ap + 8);
        if (raw >= 0) return strings.get(raw);
        return (b.get(ap + 15) & 0xFF) == 3 ? strings.get(b.getInt(ap + 16)) : null;
    }

    public static byte[] patch(byte[] axml, String newPkg, boolean changeAuthoritiesAndPerms) {
        final AxmlPatcher a = new AxmlPatcher(axml);
        final byte[] rest = Arrays.copyOfRange(axml, a.poolEnd, axml.length);
        final String oldPkg = readPackage(axml);
        final ByteBuffer rb = a.bb(rest);
        final Map<String, Integer> index = new HashMap<>();
        for (int i = 0; i < a.strings.size(); i++) index.putIfAbsent(a.strings.get(i), i);
        final List<String> added = new ArrayList<>();

        a.walk(rest, 0, (elem, ns, attr, ap, b) -> {
            String val = a.valueAt(ap, b);
            if (val == null) return;
            String nv = null;
            String nsUri = a.nsOf(ns);
            if (elem.equals("manifest") && ns == -1 && attr.equals("package")) {
                nv = newPkg;
            } else if (ANDROID_NS.equals(nsUri)) {
                if (attr.equals("name") && CLASS_ELEMS.contains(elem)) nv = qualify(val, oldPkg);
                else if (CLASS_ATTRS.contains(attr)) nv = qualify(val, oldPkg);
                else if (elem.equals("instrumentation") && attr.equals("targetPackage")) nv = swap(val, oldPkg, newPkg);
                else if (changeAuthoritiesAndPerms) {
                    if (attr.equals("authorities") && elem.equals("provider")) {
                        String[] parts = val.split(";", -1);
                        for (int i = 0; i < parts.length; i++) parts[i] = swap(parts[i], oldPkg, newPkg);
                        nv = String.join(";", parts);
                    } else if (attr.equals("name") && PERM_ELEMS.contains(elem)) nv = swap(val, oldPkg, newPkg);
                    else if (PREFIX_ATTRS.contains(attr)) nv = swap(val, oldPkg, newPkg);
                }
            }
            if (nv == null || nv.equals(val)) return;
            Integer idx = index.get(nv);
            if (idx == null) {
                idx = a.strings.size() + added.size();
                added.add(nv);
                index.put(nv, idx);
            }
            if (rb.getInt(ap + 8) >= 0) rb.putInt(ap + 8, idx);
            if ((rb.get(ap + 15) & 0xFF) == 3) rb.putInt(ap + 16, idx);
        });

        List<byte[]> all = new ArrayList<>(a.raw);
        for (String s : added) all.add(a.encode(s));
        int hdr = 28, count = all.size();
        int dataLen = 0;
        for (byte[] r : all) dataLen += r.length;
        int pad = (4 - dataLen % 4) % 4;
        int poolSize = hdr + 4 * count + dataLen + pad;
        ByteBuffer pool = a.bb(new byte[poolSize]);
        pool.putShort((short) POOL).putShort((short) hdr).putInt(poolSize).putInt(count).putInt(0);
        pool.putInt((a.utf8 ? 0x100 : 0));
        pool.putInt(hdr + 4 * count).putInt(0);
        int off = 0;
        for (byte[] r : all) { pool.putInt(off); off += r.length; }
        for (byte[] r : all) pool.put(r);

        ByteBuffer out = a.bb(new byte[8 + poolSize + rest.length]);
        out.putShort((short) XML_FILE).putShort((short) 8).putInt(8 + poolSize + rest.length);
        out.put(pool.array()).put(rest);
        return out.array();
    }

    static String qualify(String v, String pkg) {
        if (v.startsWith(".")) return pkg + v;
        if (!v.contains(".")) return pkg + "." + v;
        return v;
    }

    static String swap(String v, String oldPkg, String newPkg) {
        if (v.equals(oldPkg)) return newPkg;
        if (v.startsWith(oldPkg + ".")) return newPkg + v.substring(oldPkg.length());
        return v;
    }
}
