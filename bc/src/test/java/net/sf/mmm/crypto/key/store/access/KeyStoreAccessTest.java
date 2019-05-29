package net.sf.mmm.crypto.key.store.access;

import java.io.File;
import java.security.cert.Certificate;
import java.time.Duration;
import java.time.Instant;

import net.sf.mmm.crypto.asymmetric.cert.CertificateCreator;
import net.sf.mmm.crypto.asymmetric.cert.CertificateDataBean;
import net.sf.mmm.crypto.asymmetric.cert.CertificatePathGeneric;
import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreatorFactory;
import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair;
import net.sf.mmm.crypto.io.CryptoFileResource;
import net.sf.mmm.crypto.io.CryptoResource;
import net.sf.mmm.crypto.key.KeySet;
import net.sf.mmm.crypto.key.store.KeyStoreApi;
import net.sf.mmm.crypto.key.store.KeyStoreConfig;

import org.assertj.core.api.Assertions;

/**
 * Abstract base test for {@link KeyStoreAccess}.
 */
@SuppressWarnings({ "rawtypes" })
public class KeyStoreAccessTest extends Assertions {

  void check(KeyStoreAccess keyStoreAccess, AsymmetricKeyCreatorFactory keyFactory, CertificateCreator certificateCreator) {

    // given
    String password = "$4cret";
    KeyStoreConfig config = keyStoreAccess.getConfig();
    CryptoResource resource = config.getResource();

    // when
    AsymmetricKeyPair keyPair = keyFactory.newKeyCreator().generateKeyPair();
    KeyStoreApi keyStore = keyStoreAccess.newKeyStore();
    String alias = "alias1";
    CertificateDataBean certificateData = new CertificateDataBean();
    certificateData.setIssuer("CN=thankpoint");
    certificateData.setSubject("CN=admin@thankpoint.github.io");
    certificateData.setNotAfter(Instant.now().plus(Duration.ofDays(365)));
    certificateData.setSignatureAlgorithm("SHA256WithRSA");
    Certificate certificate = certificateCreator.generateCertificate(keyPair, certificateData);
    keyStore.setKey(alias, keyPair, password, new CertificatePathGeneric(certificate));
    keyStore.save();

    // then
    File file = null;
    if (resource instanceof CryptoFileResource) {
      file = ((CryptoFileResource) resource).getFile();
      assertThat(file).exists().isFile();
    }
    KeyStoreApi keyStore2 = keyStoreAccess.newKeyStore();
    KeySet keyPair2 = keyStore2.getKey(alias, password);
    assertThat(keyPair2).isEqualTo(keyPair);
    if (file != null) {
      file.delete();
    }
  }

}
