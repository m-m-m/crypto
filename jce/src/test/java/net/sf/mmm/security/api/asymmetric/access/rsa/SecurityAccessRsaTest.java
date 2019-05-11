/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.asymmetric.access.rsa;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;
import net.sf.mmm.security.api.asymmetric.access.SecurityAccessAsymmetricTest;
import net.sf.mmm.security.api.hash.SecurityHashConfig;

import org.junit.Test;

/**
 * Test of {@link SecurityAccessRsa}.
 */
public class SecurityAccessRsaTest extends SecurityAccessAsymmetricTest {

  /**
   * Test of {@link SecurityAccessRsa#keyLength4096()}.
   */
  @Test
  public void testRsa() {

    // given
    SecurityHashConfig hashConfig = new SecurityHashConfig(SecurityAlgorithmSha2.ALGORITHM_SHA_256, 2);
    SecurityAccessRsa rsa4096 = SecurityAccessRsa.of4096(hashConfig);
    assertThat(rsa4096.getAlgorithm()).isEqualTo("RSA");
    assertThat(rsa4096.newKeyCreator().getKeyLength()).isEqualTo(4096);

    // when + then
    verifyBidirectional(rsa4096, 512);
  }

  @Override
  protected int getSignatureLength() {

    return 512;
  }

  @Override
  protected int getPrivateKeyEncodedMinLength() {

    return 2373;
  }

  @Override
  protected int getPrivateKeyCompactMinLength() {

    return 1024;
  }

  @Override
  protected int getPrivateKeyCompactLength() {

    return 1028;
  }

  @Override
  protected int getPrivateKeyEncodedLength() {

    return 2376;
  }

  @Override
  protected int getPublicKeyCompactLength() {

    return 513;
  }

  @Override
  protected int getPublicKeyEncodedLength() {

    return 550;
  }

}
