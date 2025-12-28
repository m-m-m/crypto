package io.github.mmm.crypto.key.store.access.bc;

import java.io.File;

import org.junit.jupiter.api.Test;

import io.github.mmm.crypto.asymmetric.access.rsa.Rsa;
import io.github.mmm.crypto.asymmetric.cert.CertificateCreator;
import io.github.mmm.crypto.asymmetric.cert.access.bc.CertificateAccessX509;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreatorFactory;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.hash.sha2.Sha256;
import io.github.mmm.crypto.key.store.access.KeyStoreAccessPkcs12;

/**
 * Test of {@link KeyStoreAccessPkcs12}.
 */
public class KeyStoreAccessPkcs12Test extends KeyStoreAccessTest {

  /**
   * Test of {@link KeyStoreAccessPkcs12#of(File, String)}.
   *
   * @throws Exception on error
   */
  @SuppressWarnings("rawtypes")
  @Test
  void testX509() throws Exception {

    File keyStore = File.createTempFile("mmm.security", ".p12");
    keyStore.delete();
    String password = "$ecr4t";
    KeyStoreAccessPkcs12 access = KeyStoreAccessPkcs12.of(keyStore, password);
    AsymmetricKeyCreatorFactory keyFactory = Rsa.of4096(new HashConfig(Sha256.ALGORITHM_SHA_256));
    CertificateCreator certificateCreator = CertificateAccessX509.of().newCertificateCreator();
    check(access, keyFactory, certificateCreator);
    keyStore.deleteOnExit();
  }

}
