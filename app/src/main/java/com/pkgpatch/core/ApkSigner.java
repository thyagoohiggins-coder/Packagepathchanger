package com.pkgpatch.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/** Signs an unsigned zip with APK Signature Scheme v2. */
public final class ApkSigner {
    private static final int CHUNK = 1024 * 1024;

    public static void signV2(File unsigned, File out, SigningKey key) throws Exception {
        try (RandomAccessFile in = new RandomAccessFile(unsigned, "r")) {
            long len = in.length();
            int eocdLen = 22;
            byte[] eocd = new byte[eocdLen];
            in.seek(len - eocdLen);
            in.readFully(eocd);
            ByteBuffer e = le(eocd);
            if (e.getInt(0) != 0x06054b50) throw new IllegalStateException("EOCD not at end");
            long cdSize = e.getInt(12) & 0xFFFFFFFFL, cdOff = e.getInt(16) & 0xFFFFFFFFL;

            List<byte[]> digests = new ArrayList<>();
            digestSection(in, 0, cdOff, digests);
            digestSection(in, cdOff, cdSize, digests);
            digests.add(chunkDigest(eocd, eocd.length));

            MessageDigest top = MessageDigest.getInstance("SHA-256");
            top.update((byte) 0x5a);
            top.update(intLe(digests.size()));
            for (byte[] d : digests) top.update(d);
            byte[] contentDigest = top.digest();

            java.security.cert.X509Certificate cert = key.certificate();
            PublicKey pk = cert.getPublicKey();
            boolean ec = pk.getAlgorithm().equalsIgnoreCase("EC");
            int sigAlgo = ec ? 0x0201 : 0x0103; // both use SHA2-256 content digest
            byte[] certDer = cert.getEncoded();

            byte[] digestEntry = cat(intLe(sigAlgo), lp(contentDigest));
            byte[] digestsSeq = lp(lp(digestEntry));
            byte[] certsSeq = lp(lp(certDer));
            byte[] signedData = cat(digestsSeq, certsSeq, lp(new byte[0]));

            byte[] signature = key.sign(signedData);
            byte[] sigEntry = cat(intLe(sigAlgo), lp(signature));
            byte[] signer = cat(lp(signedData), lp(lp(sigEntry)), lp(pk.getEncoded()));
            byte[] v2Value = lp(lp(signer));

            long pairLen = 4 + v2Value.length;
            long blockSize = 8 + pairLen + 8 + 16; // pair(len+id+value) + size + magic
            ByteBuffer blk = ByteBuffer.allocate((int) (8 + blockSize)).order(ByteOrder.LITTLE_ENDIAN);
            blk.putLong(blockSize).putLong(pairLen).putInt(0x7109871a).put(v2Value);
            blk.putLong(blockSize).put("APK Sig Block 42".getBytes("US-ASCII"));

            ByteBuffer newEocd = le(eocd.clone());
            newEocd.putInt(16, (int) (cdOff + blk.capacity()));

            try (RandomAccessFile o = new RandomAccessFile(out, "rw")) {
                o.setLength(0);
                copy(in, 0, cdOff, o);
                o.write(blk.array());
                copy(in, cdOff, cdSize, o);
                o.write(newEocd.array());
            }
        }
    }

    private static void digestSection(RandomAccessFile in, long start, long size, List<byte[]> out) throws Exception {
        long pos = start, end = start + size;
        byte[] buf = new byte[CHUNK];
        while (pos < end) {
            int n = (int) Math.min(CHUNK, end - pos);
            in.seek(pos);
            in.readFully(buf, 0, n);
            out.add(chunkDigest(buf, n));
            pos += n;
        }
    }

    private static byte[] chunkDigest(byte[] buf, int n) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update((byte) 0xa5);
        md.update(intLe(n));
        md.update(buf, 0, n);
        return md.digest();
    }

    private static void copy(RandomAccessFile in, long from, long n, RandomAccessFile out) throws Exception {
        byte[] buf = new byte[65536];
        in.seek(from);
        while (n > 0) {
            int r = in.read(buf, 0, (int) Math.min(buf.length, n));
            if (r < 0) throw new java.io.EOFException();
            out.write(buf, 0, r);
            n -= r;
        }
    }

    private static ByteBuffer le(byte[] b) { return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN); }
    private static byte[] intLe(int v) { return le(new byte[4]).putInt(v).array(); }
    private static byte[] lp(byte[] d) { return cat(intLe(d.length), d); }

    private static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }
}
