/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import org.assertj.core.api.Assertions;
import org.junit.Test;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;

/**
 * Test of {@link Rsa}.
 */
public class RsaTest extends Assertions {

  /**
   * Test of {@link Rsa#keyLength4096()}.
   */
  @Test
  public void testRsa() throws Exception {

    // given
    Rsa rsa4096 = Rsa.keyLength4096();
    assertThat(rsa4096.getAlgorithm()).isEqualTo("RSA");
    assertThat(rsa4096.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(4096);

    // when
    SecurityAsymmetricKeyPair keyPair = rsa4096.generateKeyPair();
    SecurityAsymmetricCryptorFactoryBidirectional cryptorFactory = rsa4096.crypt();

    byte[] rawMessage = "Secret message".getBytes("UTF-8");
    byte[] encryptedMessage = cryptorFactory.newEncryptor(keyPair.getPrivateKey()).crypt(rawMessage, true);
    byte[] decryptedMessage = cryptorFactory.newDecryptor(keyPair.getPublicKey()).crypt(encryptedMessage, true);

    // then
    assertThat(decryptedMessage).isEqualTo(rawMessage);
    assertThat(encryptedMessage).hasSize(512);

    // and when
    encryptedMessage = cryptorFactory.newEncryptor(keyPair.getPublicKey()).crypt(rawMessage, true);
    decryptedMessage = cryptorFactory.newDecryptor(keyPair.getPrivateKey()).crypt(encryptedMessage, true);

    // then
    assertThat(decryptedMessage).isEqualTo(rawMessage);
    assertThat(encryptedMessage).hasSize(512);
  }

}
