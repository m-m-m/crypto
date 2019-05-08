package net.sf.mmm.security.api.key.store.access;

import java.io.File;
import java.security.cert.Certificate;
import java.time.Duration;
import java.time.Instant;

import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateCreator;
import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateDataBean;
import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificatePathGeneric;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.io.SecurityDataResource;
import net.sf.mmm.security.api.io.SecurityFileResource;
import net.sf.mmm.security.api.key.SecurityKeySet;
import net.sf.mmm.security.api.key.store.SecurityKeyStore;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfig;

import org.assertj.core.api.Assertions;

/**
 * Abstract base test for {@link SecurityAccessKeyStore}.
 */
@SuppressWarnings({ "rawtypes" })
public class SecurityAccessKeyStoreTest extends Assertions {

  void check(SecurityAccessKeyStore keyStoreAccess, SecurityAsymmetricKeyFactory keyFactory,
      SecurityCertificateCreator certificateCreator) {

    // given
    String password = "$4cret";
    SecurityKeyStoreConfig config = keyStoreAccess.getConfig();
    SecurityDataResource resource = config.getResource();

    // when
    SecurityAsymmetricKeyPair keyPair = keyFactory.newKeyCreator().generateKeyPair();
    SecurityKeyStore keyStore = keyStoreAccess.newKeyStore();
    String alias = "alias1";
    SecurityCertificateDataBean certificateData = new SecurityCertificateDataBean();
    certificateData.setIssuer("CN=thankpoint");
    certificateData.setSubject("CN=admin@thankpoint.github.io");
    certificateData.setNotAfter(Instant.now().plus(Duration.ofDays(365)));
    certificateData.setSignatureAlgorithm("SHA256WithRSA");
    Certificate certificate = certificateCreator.generateCertificate(keyPair, certificateData);
    keyStore.setKey(alias, keyPair, password, new SecurityCertificatePathGeneric(certificate));
    keyStore.save();

    // then
    File file = null;
    if (resource instanceof SecurityFileResource) {
      file = ((SecurityFileResource) resource).getFile();
      assertThat(file).exists().isFile();
    }
    SecurityKeyStore keyStore2 = keyStoreAccess.newKeyStore();
    SecurityKeySet keyPair2 = keyStore2.getKey(alias, password);
    assertThat(keyPair2).isEqualTo(keyPair);
    if (file != null) {
      file.delete();
    }
  }

}
