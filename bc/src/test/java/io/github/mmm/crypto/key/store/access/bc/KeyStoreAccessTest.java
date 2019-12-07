package io.github.mmm.crypto.key.store.access.bc;

import java.io.File;
import java.security.cert.Certificate;
import java.time.Duration;
import java.time.Instant;

import org.assertj.core.api.Assertions;

import io.github.mmm.crypto.asymmetric.cert.CertificateCreator;
import io.github.mmm.crypto.asymmetric.cert.CertificateDataBean;
import io.github.mmm.crypto.asymmetric.cert.CertificatePathGeneric;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreatorFactory;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair;
import io.github.mmm.crypto.io.CryptoFileResource;
import io.github.mmm.crypto.io.CryptoResource;
import io.github.mmm.crypto.key.KeySet;
import io.github.mmm.crypto.key.store.KeyStoreConfig;
import io.github.mmm.crypto.key.store.KeyStoreFacade;
import io.github.mmm.crypto.key.store.access.KeyStoreAccess;

/**
 * Abstract base test for {@link KeyStoreAccess}.
 */
@SuppressWarnings({ "rawtypes" })
public class KeyStoreAccessTest extends Assertions {

  void check(KeyStoreAccess keyStoreAccess, AsymmetricKeyCreatorFactory keyFactory,
      CertificateCreator certificateCreator) {

    // given
    String password = "$4cret";
    KeyStoreConfig config = keyStoreAccess.getConfig();
    CryptoResource resource = config.getResource();

    // when
    AsymmetricKeyPair keyPair = keyFactory.newKeyCreator().generateKeyPair();
    KeyStoreFacade keyStore = keyStoreAccess.newKeyStore();
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
    KeyStoreFacade keyStore2 = keyStoreAccess.newKeyStore();
    KeySet keyPair2 = keyStore2.getKey(alias, password);
    assertThat(keyPair2).isEqualTo(keyPair);
    if (file != null) {
      file.delete();
    }
  }

}
