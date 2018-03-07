/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import java.security.Security;

import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;

/**
 * Test of {@link Ecies}.
 */
public class EciesTest extends Assertions {

  /**
   * Test of {@link Ecies#keyLength256()}.
   */
  @Test
  public void testEcies256() throws Exception {

    // given
    Security.addProvider(new BouncyCastleProvider());
    Ecies ecies256 = Ecies.keyLength256();
    assertThat(ecies256.getAlgorithm()).isEqualTo("ECIES");
    assertThat(ecies256.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(256);

    // when
    SecurityAsymmetricKeyPair keyPair = ecies256.generateKeyPair();
    SecurityAsymmetricCryptorFactoryPublicPrivate cryptorFactory = ecies256.crypt();

    byte[] rawMessage = "Secret message".getBytes("UTF-8");
    byte[] encryptedMessage = cryptorFactory.newEncryptor(keyPair.getPublicKey()).crypt(rawMessage, true);
    byte[] decryptedMessage = cryptorFactory.newDecryptor(keyPair.getPrivateKey()).crypt(encryptedMessage, true);

    // then
    assertThat(decryptedMessage).isEqualTo(rawMessage);
    assertThat(encryptedMessage).hasSize(99);
  }

}
