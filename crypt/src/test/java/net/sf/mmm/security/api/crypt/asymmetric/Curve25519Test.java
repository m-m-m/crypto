/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;

/**
 * Test of {@link Curve25519}.
 */
public class Curve25519Test extends SecurityAsymmetricCryptorBuilderTest {

  /**
   * Test of {@link Curve25519#create()}.
   */
  @Test
  public void testCurve25519() {

    // given
    Security.addProvider(new BouncyCastleProvider());
    Curve25519 curve25519 = Curve25519.create();
    assertThat(curve25519.getAlgorithm()).isEqualTo("ECIES");
    assertThat(curve25519.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(256);

    // when + then
    verifyPublicPrivate(curve25519);
  }

  @Override
  protected int getEncryptionLength() {

    return 99;
  }

  @Override
  protected int getSignatureMinLength() {

    return 69;
  }

  @Override
  protected int getSignatureLength() {

    return 70;
  }

  @Override
  protected void verifyKeyPair(SecurityAsymmetricKeyPair keyPair, SecurityAsymmetricKeyCreator keyCreator) {

    super.verifyKeyPair(keyPair, keyCreator);
    assertThat(keyPair.getPrivateKey().getLength()).as("privateKey.length").isLessThanOrEqualTo(32);
    // TODO make 32 byte representation normal form
    // assertThat(keyPair.getPublicKey().getLength()).as("publicKey.length").isEqualTo(32);
    assertThat(keyPair.getPublicKey().getLength()).as("publicKey.length").isEqualTo(33);
  }

}
