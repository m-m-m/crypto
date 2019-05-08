/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.asymmetric.access.ec.bc;

import net.sf.mmm.binary.api.BinaryType;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;
import net.sf.mmm.security.api.asymmetric.access.SecurityAccessAsymmetricTest;
import net.sf.mmm.security.api.asymmetric.access.ec.bc.SecurityAccessCurve25519;
import net.sf.mmm.security.api.asymmetric.key.ec.bc.SecurityAsymmetricKeyCreatorEcBc;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.hash.SecurityHashConfig;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Test;

/**
 * Test of {@link SecurityAccessCurve25519}.
 */
@SuppressWarnings({ "unchecked", "rawtypes" })
public class SecurityAccessCurve25519Test extends SecurityAccessAsymmetricTest {

  private static final SecurityHashConfig HASH_CONFIG = new SecurityHashConfig(SecurityAlgorithmSha2.ALGORITHM_SHA_256);

  /**
   * Test of {@link SecurityAccessCurve25519#ofPlain(SecurityHashConfig)}.
   */
  @Test
  public void testCurve25519() {

    // given
    SecurityAccessCurve25519 curve25519 = SecurityAccessCurve25519.ofPlain(HASH_CONFIG);
    assertThat(curve25519.getAlgorithm()).isEqualTo("ECIES");
    assertThat(curve25519.newKeyCreator().getKeyLength()).isEqualTo(253);

    // when + then
    verify(curve25519, 99);
  }

  @Override
  protected int getSignatureLength() {

    return 64;
  }

  @Override
  protected int getPrivateKeyCompactMinLength() {

    return 31;
  }

  @Override
  protected int getPrivateKeyCompactLength() {

    return 32;
  }

  @Override
  protected int getPrivateKeyEncodedLength() {

    return 587;
  }

  @Override
  protected int getPublicKeyCompactLength() {

    return 33;
  }

  @Override
  protected int getPublicKeyEncodedLength() {

    return 309;
  }

  /**
   * Test of {@link SecurityAccessCurve25519#ofPlain(SecurityHashConfig)}.
   *
   * @throws Exception on error.
   */
  @Test
  public void testCurve25519Sign() throws Exception {

    SecurityAccessCurve25519 curve25519 = SecurityAccessCurve25519.ofPlain(HASH_CONFIG);
    SecurityAsymmetricKeyCreatorEcBc keyCreator = curve25519.newKeyCreator();
    BCECPrivateKey privateKey = keyCreator.createPrivateKey(BinaryType.parseBase64("BFHfTkxA/aoTaAbYRUtvl4H7upC9RIoKrcJlRQB9+8o="));
    BCECPublicKey publicKey = keyCreator.createPublicKey(BinaryType.parseBase64("AmE2wuwli7Ho2DpU/jNbbhzDKNpHnr/OogWaHA589xIG"));
    byte[] data = "Secret message".getBytes("UTF-8");
    SecuritySignature signature = curve25519.newSigner(privateKey).sign(data, true);
    String sgn = signature.formatBase64();
    String expectedSignature = "BB9yHAfP2R9UEe743Usnv2LiLtuD4qK5p6sjcsde+2oBDp7yEXVsZyelxZbRvnCwAB+o3lzxWjkX0ESGyh8Vew==";
    assertThat(sgn).isEqualTo(expectedSignature);
    boolean valid = curve25519.newVerifier(publicKey).verify(data, BinaryType.parseBase64(expectedSignature));
    assertThat(valid).isTrue();
  }

}
