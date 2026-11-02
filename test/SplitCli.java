import com.pkgpatch.core.*;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.List;

/** SplitCli keystore bundle.apks workdir newPkg : expands a bundle, repacks every APK, checks results. */
public class SplitCli {
    public static void main(String[] a) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream f = new FileInputStream(a[0])) { ks.load(f, "changeit".toCharArray()); }
        PrivateKey pk = (PrivateKey) ks.getKey("k", "changeit".toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate("k");
        SigningKey key = new SigningKey() {
            public X509Certificate certificate() { return cert; }
            public byte[] sign(byte[] d) throws Exception {
                Signature s = Signature.getInstance("SHA256withRSA"); s.initSign(pk); s.update(d); return s.sign();
            }
        };
        File dir = new File(a[2]); dir.mkdirs();
        List<File> files = ApkSet.expand(new File(a[1]), dir);
        ApkSet set = ApkSet.of(files);
        check(set.packageName.equals("com.example.old"), "pkg");
        check(set.splits.size() == 2, "splits=" + set.splits.size());
        File out = new File(dir, "out"); out.mkdirs();
        List<File> res = set.repack(out, a[3], true, key);
        check(res.size() == 3, "outputs");
        check(ApkRepacker.readSplit(res.get(0)) == null, "base first");
        for (File r : res) {
            check(ApkRepacker.readPackage(r).equals(a[3]), "package of " + r);
            System.out.println(r.getPath() + " split=" + ApkRepacker.readSplit(r));
        }
        // plain APK passes through expand unchanged
        check(ApkSet.expand(set.base, dir).get(0).equals(set.base), "plain apk");
        // errors: two bases / only splits
        expectFail(() -> ApkSet.of(List.of(set.base, set.base)), "two bases");
        expectFail(() -> ApkSet.of(set.splits), "no base");
        System.out.println("SPLIT CHECKS PASSED");
    }
    interface X { void run() throws Exception; }
    static void expectFail(X x, String m) { try { x.run(); } catch (Exception e) { return; } throw new AssertionError(m); }
    static void check(boolean b, String m) { if (!b) throw new AssertionError(m); }
}
