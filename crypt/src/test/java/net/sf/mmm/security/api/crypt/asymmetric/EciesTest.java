/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
    Security.addProvider(new BouncyCastleProvider());
    Ecies ecies256 = Ecies.keyLength256();
    assertThat(ecies256.getAlgorithm()).isEqualTo("ECIES");
    assertThat(ecies256.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(256);

    // when + then
    verifyPublicPrivate(ecies256);
  }

  @Override
  protected int getEncryptionLength() {

    return 99;
  }

  @Override
  protected int getSignatureMinLength() {

    return 70;
  }

  @Override
  protected int getSignatureLength() {

    return 72;
  }

}
