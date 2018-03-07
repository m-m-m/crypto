/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import java.security.Security;

import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;

/**
 * Test of {@link Curve25519}.
 */
public class Curve25519Test extends Assertions {

  /**
   * Test of {@link Curve25519#create()}.
   */
  @Test
  public void testCurve25519() throws Exception {

    // given
    Security.addProvider(new BouncyCastleProvider());
    Curve25519 curve25519 = Curve25519.create();
    assertThat(curve25519.getAlgorithm()).isEqualTo("ECIES");
    assertThat(curve25519.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(256);

    // when
    SecurityAsymmetricKeyPair keyPair = curve25519.generateKeyPair();
    SecurityAsymmetricCryptorFactoryPublicPrivate cryptorFactory = curve25519.crypt();

    byte[] rawMessage = "Secret message".getBytes("UTF-8");
    byte[] encryptedMessage = cryptorFactory.newEncryptor(keyPair.getPublicKey()).crypt(rawMessage, true);
    byte[] decryptedMessage = cryptorFactory.newDecryptor(keyPair.getPrivateKey()).crypt(encryptedMessage, true);

    // then
    assertThat(decryptedMessage).isEqualTo(rawMessage);
    assertThat(encryptedMessage).hasSize(99);
  }

}
