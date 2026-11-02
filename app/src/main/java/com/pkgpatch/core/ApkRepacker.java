package com.pkgpatch.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.Inflater;

/** Rewrites an APK with a new package name and re-signs it (v2). */
public final class ApkRepacker {
    private static final class Entry {
        byte[] name; int flags, method, time, date, crc, csize, usize, intAttr, extAttr; long localOff;
        String str() { return new String(name, StandardCharsets.UTF_8); }
    }

    public static String readPackage(File apk) throws Exception { return AxmlPatcher.readPackage(readManifest(apk)); }

    /** Split name of a split APK, or null when it is a base APK. */
    public static String readSplit(File apk) throws Exception { return AxmlPatcher.readSplit(readManifest(apk)); }

    static byte[] readManifest(File apk) throws Exception {
        try (RandomAccessFile in = new RandomAccessFile(apk, "r")) {
            for (Entry e : entries(in))
                if (e.str().equals("AndroidManifest.xml")) return read(in, e);
        }
        throw new IllegalArgumentException("AndroidManifest.xml not found in " + apk.getName());
    }

    public static void repack(File apk, File out, String newPkg, boolean authAndPerms, SigningKey key) throws Exception {
        File tmp = new File(out.getPath() + ".unsigned");
        try {
            try (RandomAccessFile in = new RandomAccessFile(apk, "r");
                 RandomAccessFile o = new RandomAccessFile(tmp, "rw")) {
                o.setLength(0);
                List<Entry> kept = new ArrayList<>();
                List<Long> offs = new ArrayList<>();
                boolean manifest = false;
                for (Entry e : entries(in)) {
                    String n = e.str();
                    if (isSignature(n)) continue;
                    long pos = o.getFilePointer();
                    byte[] data = null;
                    if (n.equals("AndroidManifest.xml")) {
                        byte[] m = AxmlPatcher.patch(read(in, e), newPkg, authAndPerms);
                        CRC32 c = new CRC32(); c.update(m);
                        e.method = 0; e.crc = (int) c.getValue(); e.csize = e.usize = m.length;
                        data = m; manifest = true;
                    }
                    writeLocal(o, e, data == null ? 0 : 1);
                    if (data != null) o.write(data); else copyRaw(in, e, o);
                    offs.add(pos);
                    kept.add(e);
                }
                if (!manifest) throw new IllegalArgumentException("AndroidManifest.xml not found");
                long cdStart = o.getFilePointer();
                ByteArrayOutputStream cd = new ByteArrayOutputStream();
                for (int i = 0; i < kept.size(); i++) cd.write(central(kept.get(i), offs.get(i)));
                o.write(cd.toByteArray());
                ByteBuffer eo = le(22);
                eo.putInt(0x06054b50).putShort((short) 0).putShort((short) 0)
                        .putShort((short) kept.size()).putShort((short) kept.size())
                        .putInt(cd.size()).putInt((int) cdStart).putShort((short) 0);
                o.write(eo.array());
            }
            ApkSigner.signV2(tmp, out, key);
        } finally {
            tmp.delete();
        }
    }

    private static boolean isSignature(String n) {
        if (!n.startsWith("META-INF/") || n.indexOf('/', 9) >= 0) return false;
        String u = n.toUpperCase();
        return u.equals("META-INF/MANIFEST.MF") || u.endsWith(".SF") || u.endsWith(".RSA")
                || u.endsWith(".DSA") || u.endsWith(".EC");
    }

    private static ByteBuffer le(int n) { return ByteBuffer.allocate(n).order(ByteOrder.LITTLE_ENDIAN); }

    private static void writeLocal(RandomAccessFile o, Entry e, int fixedSize) throws Exception {
        long dataOff = o.getFilePointer() + 30 + e.name.length;
        int pad = 0;
        if (e.method == 0) {
            int align = e.str().endsWith(".so") ? 4096 : 4;
            pad = (int) ((align - dataOff % align) % align);
            if (pad > 0 && pad < 4) pad += align;
        }
        ByteBuffer h = le(30 + e.name.length + pad);
        h.putInt(0x04034b50).putShort((short) 20).putShort((short) (e.flags & 0x0800))
                .putShort((short) e.method).putShort((short) e.time).putShort((short) e.date)
                .putInt(e.crc).putInt(e.csize).putInt(e.usize)
                .putShort((short) e.name.length).putShort((short) pad);
        h.put(e.name);
        if (pad > 0) h.putShort((short) 0xD935).putShort((short) (pad - 4));
        o.write(h.array());
    }

    private static byte[] central(Entry e, long localOff) {
        ByteBuffer b = le(46 + e.name.length);
        b.putInt(0x02014b50).putShort((short) 20).putShort((short) 20).putShort((short) (e.flags & 0x0800))
                .putShort((short) e.method).putShort((short) e.time).putShort((short) e.date)
                .putInt(e.crc).putInt(e.csize).putInt(e.usize).putShort((short) e.name.length)
                .putShort((short) 0).putShort((short) 0).putShort((short) 0).putShort((short) e.intAttr)
                .putInt(e.extAttr).putInt((int) localOff).put(e.name);
        return b.array();
    }

    private static List<Entry> entries(RandomAccessFile in) throws Exception {
        long len = in.length();
        int max = (int) Math.min(len, 65557);
        byte[] tail = new byte[max];
        in.seek(len - max);
        in.readFully(tail);
        int p = max - 22;
        while (p >= 0 && le(tail, p) != 0x06054b50) p--;
        if (p < 0) throw new IllegalArgumentException("Not a zip file");
        ByteBuffer t = ByteBuffer.wrap(tail).order(ByteOrder.LITTLE_ENDIAN);
        int count = t.getShort(p + 10) & 0xFFFF;
        long cdSize = t.getInt(p + 12) & 0xFFFFFFFFL, cdOff = t.getInt(p + 16) & 0xFFFFFFFFL;
        if (cdOff == 0xFFFFFFFFL || count == 0xFFFF) throw new IllegalArgumentException("Zip64 unsupported");
        byte[] cd = new byte[(int) cdSize];
        in.seek(cdOff);
        in.readFully(cd);
        ByteBuffer c = ByteBuffer.wrap(cd).order(ByteOrder.LITTLE_ENDIAN);
        List<Entry> list = new ArrayList<>();
        int q = 0;
        for (int i = 0; i < count; i++) {
            if (c.getInt(q) != 0x02014b50) throw new IllegalArgumentException("Bad central directory");
            Entry e = new Entry();
            e.flags = c.getShort(q + 8) & 0xFFFF; e.method = c.getShort(q + 10) & 0xFFFF;
            e.time = c.getShort(q + 12) & 0xFFFF; e.date = c.getShort(q + 14) & 0xFFFF;
            e.crc = c.getInt(q + 16); e.csize = c.getInt(q + 20); e.usize = c.getInt(q + 24);
            int nl = c.getShort(q + 28) & 0xFFFF, xl = c.getShort(q + 30) & 0xFFFF, cl = c.getShort(q + 32) & 0xFFFF;
            e.intAttr = c.getShort(q + 36) & 0xFFFF; e.extAttr = c.getInt(q + 38);
            e.localOff = c.getInt(q + 42) & 0xFFFFFFFFL;
            e.name = new byte[nl];
            System.arraycopy(cd, q + 46, e.name, 0, nl);
            list.add(e);
            q += 46 + nl + xl + cl;
        }
        return list;
    }

    private static int le(byte[] b, int p) {
        return (b[p] & 0xFF) | (b[p + 1] & 0xFF) << 8 | (b[p + 2] & 0xFF) << 16 | (b[p + 3] & 0xFF) << 24;
    }

    private static long dataOffset(RandomAccessFile in, Entry e) throws Exception {
        byte[] h = new byte[30];
        in.seek(e.localOff);
        in.readFully(h);
        ByteBuffer b = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN);
        return e.localOff + 30 + (b.getShort(26) & 0xFFFF) + (b.getShort(28) & 0xFFFF);
    }

    private static void copyRaw(RandomAccessFile in, Entry e, RandomAccessFile o) throws Exception {
        in.seek(dataOffset(in, e));
        long n = e.csize & 0xFFFFFFFFL;
        byte[] buf = new byte[65536];
        while (n > 0) {
            int r = in.read(buf, 0, (int) Math.min(buf.length, n));
            if (r < 0) throw new java.io.EOFException();
            o.write(buf, 0, r);
            n -= r;
        }
    }

    private static byte[] read(RandomAccessFile in, Entry e) throws Exception {
        byte[] c = new byte[e.csize];
        in.seek(dataOffset(in, e));
        in.readFully(c);
        if (e.method == 0) return c;
        Inflater inf = new Inflater(true);
        inf.setInput(c);
        byte[] out = new byte[e.usize];
        int n = 0;
        while (n < out.length && !inf.finished()) n += inf.inflate(out, n, out.length - n);
        inf.end();
        return out;
    }
}
