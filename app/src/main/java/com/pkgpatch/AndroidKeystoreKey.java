package com.pkgpatch;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.pkgpatch.core.SigningKey;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

final class AndroidKeystoreKey implements SigningKey {
    private static final String ALIAS = "pkgpatch";
    private final KeyStore ks;

    AndroidKeystoreKey() throws Exception {
        ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(ALIAS)) {
            KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            g.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setKeySize(2048)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setCertificateSubject(new X500Principal("CN=Package Patcher"))
                    .setCertificateNotBefore(new Date(System.currentTimeMillis() - 86400000L))
                    .setCertificateNotAfter(new Date(System.currentTimeMillis() + 30L * 365 * 86400000L))
                    .build());
            g.generateKeyPair();
        }
    }

    @Override public X509Certificate certificate() throws Exception {
        return (X509Certificate) ks.getCertificate(ALIAS);
    }

    @Override public byte[] sign(byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign((PrivateKey) ks.getKey(ALIAS, null));
        s.update(data);
        return s.sign();
    }
}
