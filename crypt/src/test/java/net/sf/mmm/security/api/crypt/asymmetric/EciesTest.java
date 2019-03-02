/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import org.junit.Test;

/**
 * Test of {@link Ecies}.
 */
public class EciesTest extends SecurityAsymmetricCryptorBuilderTest {

  /**
   * Test of {@link Ecies#keyLength256()}.
   */
  @Test
  public void testEcies256() {

    // given
    Ecies ecies256 = Ecies.keyLength256();
    assertThat(ecies256.getAlgorithm()).isEqualTo("ECIES");
    assertThat(ecies256.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(256);

    // when + then
    verify(ecies256, 99);
  }

  @Override
  protected int getSignatureMinLength() {

    return 70;
  }

  @Override
  protected int getSignatureLength() {

    return 72;
  }

  @Override
  protected int getPrivateKeyCompactLength() {

    // return 32;
    return 67;
  }

  @Override
  protected int getPrivateKeyEncodedLength() {

    return 67;
  }

  @Override
  protected int getPublicKeyCompactLength() {

    // return 33;
    return 91;
  }

  @Override
  protected int getPublicKeyEncodedLength() {

    return 91;
  }

}
