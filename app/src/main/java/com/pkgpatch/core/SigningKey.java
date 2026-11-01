package com.pkgpatch.core;

import java.security.cert.X509Certificate;

public interface SigningKey {
    X509Certificate certificate() throws Exception;
    byte[] sign(byte[] data) throws Exception;
}
