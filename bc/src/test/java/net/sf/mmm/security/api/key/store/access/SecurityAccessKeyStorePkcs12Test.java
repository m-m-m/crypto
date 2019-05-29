package net.sf.mmm.security.api.key.store.access;

import java.io.File;

import net.sf.mmm.security.api.asymmetric.access.rsa.Rsa;
import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateCreator;
import net.sf.mmm.security.api.asymmetric.cert.access.SecurityAccessCertificateX509;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.sha2.Sha256;

import org.junit.Test;

/**
 * Test of {@link SecurityAccessKeyStorePkcs12}.
 */
public class SecurityAccessKeyStorePkcs12Test extends SecurityAccessKeyStoreTest {

  /**
   * Test of {@link SecurityAccessKeyStorePkcs12#of(File, String)}.
   *
   * @throws Exception on error
   */
  @SuppressWarnings("rawtypes")
  @Test
  public void testX509() throws Exception {

    File keyStore = File.createTempFile("mmm.security", ".p12");
    keyStore.delete();
    String password = "$ecr4t";
    SecurityAccessKeyStorePkcs12 access = SecurityAccessKeyStorePkcs12.of(keyStore, password);
    SecurityAsymmetricKeyFactory keyFactory = Rsa.of4096(new SecurityHashConfig(Sha256.ALGORITHM_SHA_256));
    SecurityCertificateCreator certificateCreator = SecurityAccessCertificateX509.of().newCertificateCreator();
    check(access, keyFactory, certificateCreator);
    keyStore.deleteOnExit();
  }

}
