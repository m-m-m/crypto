/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package io.github.mmm.crypto.asymmetric.access.ec.bc;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.jupiter.api.Test;

import io.github.mmm.binary.BinaryType;
import io.github.mmm.crypto.asymmetric.key.ec.bc.AsymmetricKeyCreatorEcBc;
import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.hash.sha2.Sha256;

/**
 * Test of {@link Curve25519}.
 */
@SuppressWarnings({ "unchecked", "rawtypes" })
public class Curve25519Test extends AsymmetricAccessTest {

  /**
   * Test of {@link Curve25519#ofPlain(HashConfig)}.
   */
  @Test
  public void testCurve25519() {

    // given
    Curve25519 curve25519 = Curve25519.ofPlain(Sha256.SHA_256);
    assertThat(curve25519.getSignatureConfig().getHashConfig().getAlgorithm()).isEqualTo("SHA-256")
        .isEqualTo(Sha256.ALGORITHM_SHA_256);
    assertThat(curve25519.getSignatureConfig().getSignatureAlgorithm().getHashAlgorithm()).isEqualTo("SHA-256");
    assertThat(curve25519.getSignatureConfig().getSignatureAlgorithm().getSigningAlgorithm()).isEqualTo("ECDSA");
    assertThat(curve25519.getCryptorConfig().getAlgorithm()).isEqualTo("ECIES");
    assertThat(curve25519.newKeyCreator().getKeyLength()).isEqualTo(253);

    // when + then
    verify(curve25519, 99);
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
   * Test of {@link Curve25519#ofPlain(HashConfig)}.
   *
   * @throws Exception on error.
   */
  @Test
  public void testCurve25519Sign() throws Exception {

    Curve25519 curve25519 = Curve25519.ofPlain(Sha256.ALGORITHM_SHA_256);
    AsymmetricKeyCreatorEcBc keyCreator = curve25519.newKeyCreator();
    BCECPrivateKey privateKey = keyCreator
        .createPrivateKey(BinaryType.parseBase64("BFHfTkxA/aoTaAbYRUtvl4H7upC9RIoKrcJlRQB9+8o="));
    BCECPublicKey publicKey = keyCreator
        .createPublicKey(BinaryType.parseBase64("AmE2wuwli7Ho2DpU/jNbbhzDKNpHnr/OogWaHA589xIG"));
    byte[] data = "Secret message".getBytes("UTF-8");

    SignatureBinary signature = curve25519.newSigner(privateKey).sign(data, true);
    String sgn = signature.formatBase64();
    String expectedSignature = "AaTxkCZk6Q42eDNUj7PHuUuXkGRRgVmngto2u6FpV+kDqpUkbafS702dNB7x7AhGFgUnnGBl66fngbFPmWk70A==";
    assertThat(sgn).isEqualTo(expectedSignature);
    boolean valid = curve25519.newVerifier(publicKey).verify(data, BinaryType.parseBase64(expectedSignature));
    assertThat(valid).isTrue();

    signature = curve25519.getSignatureFactoryWithoutHash().newSigner(privateKey).sign(data, true);
    sgn = signature.formatBase64();
    expectedSignature = "BB9yHAfP2R9UEe743Usnv2LiLtuD4qK5p6sjcsde+2oBDp7yEXVsZyelxZbRvnCwAB+o3lzxWjkX0ESGyh8Vew==";
    assertThat(sgn).isEqualTo(expectedSignature);
    valid = curve25519.getSignatureFactoryWithoutHash().newVerifier(publicKey).verify(data,
        BinaryType.parseBase64(expectedSignature));
    assertThat(valid).isTrue();
  }

}
