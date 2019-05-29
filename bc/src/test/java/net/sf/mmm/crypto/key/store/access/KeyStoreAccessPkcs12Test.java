package net.sf.mmm.crypto.key.store.access;

import java.io.File;

import net.sf.mmm.crypto.asymmetric.access.rsa.Rsa;
import net.sf.mmm.crypto.asymmetric.cert.CertificateCreator;
import net.sf.mmm.crypto.asymmetric.cert.access.CertificateAccessX509;
import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyFactory;
import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.hash.sha2.Sha256;

import org.junit.Test;

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
  public void testX509() throws Exception {

    File keyStore = File.createTempFile("mmm.security", ".p12");
    keyStore.delete();
    String password = "$ecr4t";
    KeyStoreAccessPkcs12 access = KeyStoreAccessPkcs12.of(keyStore, password);
    AsymmetricKeyFactory keyFactory = Rsa.of4096(new HashConfig(Sha256.ALGORITHM_SHA_256));
    CertificateCreator certificateCreator = CertificateAccessX509.of().newCertificateCreator();
    check(access, keyFactory, certificateCreator);
    keyStore.deleteOnExit();
  }

}
