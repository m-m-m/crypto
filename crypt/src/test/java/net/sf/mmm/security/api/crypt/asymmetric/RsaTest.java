/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import org.junit.Test;

/**
 * Test of {@link Rsa}.
 */
public class RsaTest extends SecurityAsymmetricCryptorBuilderTest {

  /**
   * Test of {@link Rsa#keyLength4096()}.
   */
  @Test
  public void testRsa() {

    // given
    Rsa rsa4096 = Rsa.keyLength4096();
    assertThat(rsa4096.getAlgorithm()).isEqualTo("RSA");
    assertThat(rsa4096.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(4096);

    // when + then
    verifyBidirectional(rsa4096);
  }

  @Override
  protected int getEncryptionLength() {

    return 512;
  }

  @Override
  protected int getSignatureLength() {

    return 512;
  }

}
