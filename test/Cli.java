import com.pkgpatch.core.*;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

public class Cli {
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
        System.out.println("old=" + ApkRepacker.readPackage(new File(a[1])));
        ApkRepacker.repack(new File(a[1]), new File(a[2]), a[3], true, key);
        System.out.println("new=" + ApkRepacker.readPackage(new File(a[2])));
    }
}
