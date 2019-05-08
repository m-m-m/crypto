/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.asymmetric.access;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.hash.SecurityHash;

import org.assertj.core.api.AbstractIntegerAssert;
import org.assertj.core.api.Assertions;

/**
 * Abstract test class for {@link SecurityAccessAsymmetric}.
 */
public abstract class SecurityAccessAsymmetricTest extends Assertions {

  /**
   * @param access the {@link AbstractSecurityAsymmetricCryptoraccessPrivatePublic} to test.
   */
  protected void verify(SecurityAccessAsymmetric<?, ?, ?, ?, ?> access, int encryptionLength) {

    verify((SecurityAccessAsymmetric) access, encryptionLength, false);
  }

  /**
   * @param access the {@link AbstractSecurityAsymmetricCryptoraccessBidirectional} to test.
   */
  protected void verifyBidirectional(SecurityAccessAsymmetric<?, ?, ?, ?, ?> access, int encryptionLength) {

    verify((SecurityAccessAsymmetric) access, encryptionLength, true);
  }

  private void verify(SecurityAccessAsymmetric<SecuritySignature, PrivateKey, PublicKey, ?, ?> access, int encryptionLength,
      boolean bidirectional) {

    SecurityAsymmetricKeyCreator<PrivateKey, PublicKey, ?> keyCreator = access.newKeyCreator();
    SecurityAsymmetricKeyPair keyPair = keyCreator.generateKeyPair();
    verifyKeyPair(keyPair, keyCreator);
    // encryption
    byte[] rawMessage = "Secret message".getBytes(StandardCharsets.UTF_8);
    PublicKey publicKey = keyPair.getPublicKey();
    PrivateKey privateKey = keyPair.getPrivateKey();
    verifyCrypt(access.newEncryptor(publicKey), access.newDecryptor(privateKey), rawMessage, encryptionLength);
    if (bidirectional) {
      verifyCrypt(access.newEncryptorUnsafe(privateKey), access.newDecryptorUnsafe(publicKey), rawMessage, encryptionLength);
    }
    // signing
    SecurityHash data = new SecurityHash(rawMessage);
    SecuritySignature signature = access.newSigner(privateKey).sign(data, true);
    boolean signatureVerified = access.newVerifier(publicKey).verify(data, signature);
    assertThat(signatureVerified).as("signature verified").isTrue();
    verifySignature(signature);
  }

  /**
   * @param keyPair the {@link SecurityAsymmetricKeyPair} to verify.
   * @param keyCreator the {@link SecurityAsymmetricKeyCreator}.
   */
  protected void verifyKeyPair(SecurityAsymmetricKeyPair keyPair, SecurityAsymmetricKeyCreator keyCreator) {

    // verify private key
    PrivateKey privateKey = keyPair.getPrivateKey();
    byte[] privateKeyData = keyCreator.asData(privateKey);
    assertThat(privateKeyData.length).isBetween(getPrivateKeyCompactMinLength(), getPrivateKeyCompactLength());
    PrivateKey deserializePrivateKey = keyCreator.createPrivateKey(privateKeyData);
    // assertThat(deserializePrivateKey).isEqualTo(privateKey);
    byte[] encoded = privateKey.getEncoded();
    assertThat(encoded.length).isBetween(getPrivateKeyEncodedMinLength(), getPrivateKeyEncodedLength());
    if (!Arrays.equals(privateKeyData, encoded)) {
      deserializePrivateKey = keyCreator.createPrivateKey(encoded);
      assertThat(deserializePrivateKey).isEqualTo(privateKey);
    }

    // verify public key
    PublicKey publicKey = keyPair.getPublicKey();
    byte[] publicKeyData = keyCreator.asData(publicKey);
    assertThat(publicKeyData.length).isBetween(getPublicKeyCompactMinLength(), getPublicKeyCompactLength());
    PublicKey deserializePublicKey = keyCreator.createPublicKey(publicKeyData);
    assertThat(deserializePublicKey).isEqualTo(publicKey);
    encoded = publicKey.getEncoded();
    assertThat(encoded.length).isBetween(getPublicKeyEncodedMinLength(), getPublicKeyEncodedLength());
    if (!Arrays.equals(publicKeyData, encoded)) {
      deserializePublicKey = keyCreator.createPublicKey(encoded);
      assertThat(deserializePublicKey).isEqualTo(publicKey);
    }
  }

  /**
   * @return the expected (maximum) length in bytes of the signature of a SHA-256 hash.
   */
  protected abstract int getSignatureLength();

  /**
   * @return the expected minimum length in bytes of the signature of a SHA-256 hash.
   */
  protected int getSignatureMinLength() {

    return getSignatureLength();
  }

  /**
   * @return the expected (maximum) length in bytes of the {@link SecurityPublicKey#getData() compact public key data}.
   */
  protected int getPublicKeyCompactLength() {

    return getPublicKeyEncodedLength();
  }

  /**
   * @return the expected (minimum) length in bytes of the {@link SecurityPublicKey#getData() compact public key data}.
   */
  protected int getPublicKeyCompactMinLength() {

    if (getPublicKeyCompactLength() == getPublicKeyEncodedLength()) {
      return getPublicKeyEncodedMinLength();
    } else {
      return getPublicKeyCompactLength();
    }
  }

  /**
   * @return the expected (maximum) length in bytes of the {@link java.security.PublicKey#getEncoded() encoded public
   *         key data}.
   */
  protected abstract int getPublicKeyEncodedLength();

  /**
   * @return the expected (minimum) length in bytes of the {@link java.security.PublicKey#getEncoded() encoded public
   *         key data}.
   */
  protected int getPublicKeyEncodedMinLength() {

    return getPublicKeyEncodedLength();
  }

  /**
   * @return the expected (maximum) length in bytes of the {@link SecurityPrivateKey#getData() compact private key
   *         data}.
   */
  protected int getPrivateKeyCompactLength() {

    return getPrivateKeyEncodedLength();
  }

  /**
   * @return the expected (minimum) length in bytes of the {@link SecurityPrivateKey#getData() compact private key
   *         data}.
   */
  protected int getPrivateKeyCompactMinLength() {

    if (getPrivateKeyCompactLength() == getPrivateKeyEncodedLength()) {
      return getPrivateKeyEncodedMinLength();
    } else {
      return getPrivateKeyCompactLength();
    }
  }

  /**
   * @return the expected (maximum) length in bytes of the {@link java.security.PrivateKey#getEncoded() encoded private
   *         key data}.
   */
  protected abstract int getPrivateKeyEncodedLength();

  /**
   * @return the expected (minimum) length in bytes of the {@link java.security.PrivateKey#getEncoded() encoded private
   *         key data}.
   */
  protected int getPrivateKeyEncodedMinLength() {

    return getPrivateKeyEncodedLength();
  }

  /**
   * @param signature the {@link SecuritySignature} to verify.
   */
  protected void verifySignature(SecuritySignature signature) {

    int signatureLength = getSignatureLength();
    if (signatureLength > 0) {
      int signatureMinLength = getSignatureMinLength();
      AbstractIntegerAssert<?> length = assertThat(signature.getLength()).as("signature.length");
      if (signatureMinLength == signatureLength) {
        length.isEqualTo(signatureLength);
      } else {
        length.isBetween(Integer.valueOf(signatureMinLength), Integer.valueOf(signatureLength));
      }
    }
  }

  private void verifyCrypt(SecurityEncryptor encryptor, SecurityDecryptor decryptor, byte[] rawMessage, int encryptionLength) {

    byte[] encryptedMessage = encryptor.crypt(rawMessage, true);
    byte[] decryptedMessage = decryptor.crypt(encryptedMessage, true);
    assertThat(decryptedMessage).isEqualTo(rawMessage);

    if (encryptionLength > 0) {
      assertThat(encryptedMessage).hasSize(encryptionLength);
    }
  }

}
