/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.crypto.asymmetric.access.rsa;

import net.sf.mmm.crypto.asymmetric.access.AsymmetricAccessTest;
import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.hash.sha2.Sha256;

import org.junit.Test;

/**
 * Test of {@link Rsa}.
 */
public class RsaTest extends AsymmetricAccessTest {

  /**
   * Test of {@link Rsa#keyLength4096()}.
   */
  @Test
  public void testRsa() {

    // given
    HashConfig hashConfig = new HashConfig(Sha256.ALGORITHM_SHA_256, 2);
    Rsa rsa4096 = Rsa.of4096(hashConfig);
    assertThat(rsa4096.getCryptorConfig().getAlgorithm()).isEqualTo("RSA");
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

    return 2370;
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

    return 2378;
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
