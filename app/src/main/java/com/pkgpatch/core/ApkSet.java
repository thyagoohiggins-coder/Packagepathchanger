package com.pkgpatch.core;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** A base APK plus its split APKs (from an installed app, several picked files or an .apks/.xapk bundle). */
public final class ApkSet {
    public final File base;
    public final List<File> splits;
    public final String packageName;

    private ApkSet(File base, List<File> splits, String pkg) { this.base = base; this.splits = splits; this.packageName = pkg; }

    public List<File> all() {
        List<File> l = new ArrayList<>();
        l.add(base); l.addAll(splits);
        return l;
    }

    /** Expands bundles (zip files containing .apk entries) into {@code dir}; plain APKs are returned as-is. */
    public static List<File> expand(File f, File dir) throws Exception {
        List<File> out = new ArrayList<>();
        try (ZipFile z = new ZipFile(f)) {
            if (z.getEntry("AndroidManifest.xml") != null) { out.add(f); return out; }
            Enumeration<? extends ZipEntry> en = z.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String n = e.getName();
                if (e.isDirectory() || !n.toLowerCase().endsWith(".apk")) continue;
                String safe = n.replaceAll("[^A-Za-z0-9._-]", "_");
                File t = new File(dir, out.size() + "_" + safe);
                try (InputStream in = z.getInputStream(e); OutputStream o = new FileOutputStream(t)) {
                    byte[] buf = new byte[65536]; int r;
                    while ((r = in.read(buf)) > 0) o.write(buf, 0, r);
                }
                out.add(t);
            }
        }
        if (out.isEmpty()) throw new IllegalArgumentException(f.getName() + " não contém APKs");
        return out;
    }

    /** Validates that the files form exactly one base APK plus splits of the same package. */
    public static ApkSet of(List<File> apks) throws Exception {
        File base = null;
        List<File> splits = new ArrayList<>();
        String pkg = null;
        for (File f : apks) {
            String p = ApkRepacker.readPackage(f);
            if (pkg == null) pkg = p;
            else if (!pkg.equals(p)) throw new IllegalArgumentException("APKs de pacotes diferentes: " + pkg + " e " + p);
            if (ApkRepacker.readSplit(f) == null) {
                if (base != null) throw new IllegalArgumentException("Mais de um APK base selecionado");
                base = f;
            } else splits.add(f);
        }
        if (base == null) throw new IllegalArgumentException("APK base não encontrado (só splits)");
        return new ApkSet(base, splits, pkg);
    }

    /** Repacks every APK of the set with the same key; returns the outputs, base first. */
    public List<File> repack(File outDir, String newPkg, boolean authAndPerms, SigningKey key) throws Exception {
        List<File> out = new ArrayList<>();
        int i = 0;
        for (File f : all()) {
            File o = new File(outDir, (i++) + ".apk");
            ApkRepacker.repack(f, o, newPkg, authAndPerms, key);
            out.add(o);
        }
        return out;
    }
}
