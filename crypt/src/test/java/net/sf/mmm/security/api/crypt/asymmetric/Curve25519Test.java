/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.hash.SecurityHashConfigSha256;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.util.datatype.api.BinaryType;

import org.junit.Ignore;
import org.junit.Test;

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
    Curve25519 curve25519 = Curve25519.create();
    assertThat(curve25519.getAlgorithm()).isEqualTo("ECIES");
    assertThat(curve25519.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(256);

    // when + then
    verify(curve25519, 99);
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

  @Override
  protected void verifyKeyPair(SecurityAsymmetricKeyPair keyPair, SecurityAsymmetricKeyCreator keyCreator) {

    super.verifyKeyPair(keyPair, keyCreator);
    assertThat(keyPair.getPrivateKey().getLength()).as("privateKey.length").isLessThanOrEqualTo(32);
    // TODO make 32 byte representation normal form
    // assertThat(keyPair.getPublicKey().getLength()).as("publicKey.length").isEqualTo(32);
    assertThat(keyPair.getPublicKey().getLength()).as("publicKey.length").isEqualTo(33);
  }

  @Test
  @Ignore
  public void testCurve25519Sign() throws Exception {

    Curve25519 curve25519 = Curve25519.create();
    SecurityAsymmetricKeyCreator keyCreator = curve25519.newKeyCreator();
    SecurityPrivateKey privateKey = keyCreator.deserializePrivateKey("yKsX5ek8Fi/xfzZL1pO/OZXZ3ONPdFJCWa27JXNSUWc=");
    SecurityPublicKey publicKey = keyCreator.deserializePublicKey("MWRq2d8BvrsFV5ZTD3I6lkXElkCNQ209oQJytX9A7wQ=");
    curve25519.hash(new SecurityHashConfigSha256(2));
    SecuritySignatureFactory signatureFactory = curve25519.sign();
    byte[] data = "Secret message".getBytes("UTF-8");
    byte[] signature = signatureFactory.newSigner(privateKey).sign(data, true);
    String sgn = BinaryType.formatHex(signature);
    System.out.println(sgn);
    String expectedSignature = "Rz9yg6Ja1mHF8Ajq27jey3A1fEapLPkbXCxMQ7CXxQ51mZGI4S50Fx8PbNCPkfwBrUudSUZbSqaEok0bs84WIg==";
    String expectedSgn = BinaryType.formatHex(BinaryType.parseBase64(expectedSignature));
    assertThat(sgn).isEqualTo(expectedSgn);
    boolean valid = signatureFactory.newVerifier(publicKey).verify(data, BinaryType.parseBase64(expectedSignature));
    assertThat(valid).isTrue();
  }

}
