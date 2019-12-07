/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package io.github.mmm.crypto.asymmetric.access.ec.bc;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import org.assertj.core.api.AbstractIntegerAssert;
import org.assertj.core.api.Assertions;

import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.asymmetric.access.AsymmetricAccess;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair;
import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;
import io.github.mmm.crypto.crypt.Decryptor;
import io.github.mmm.crypto.crypt.Encryptor;

/**
 * Abstract test class for {@link AsymmetricAccess}.
 */
@SuppressWarnings({ "unchecked", "rawtypes" })
public abstract class AsymmetricAccessTest extends Assertions {

  /**
   * @param access the {@link AsymmetricAccess} to test.
   * @param encryptionLength the expected encrypted data length of the message "Secret message".
   */
  protected void verify(AsymmetricAccess<?, ?, ?, ?, ?> access, int encryptionLength) {

    verify((AsymmetricAccess) access, encryptionLength, false);
  }

  /**
   * @param access the {@link AsymmetricAccess} to test.
   * @param encryptionLength the expected encrypted data length of the message "Secret message".
   */
  protected void verifyBidirectional(AsymmetricAccess<?, ?, ?, ?, ?> access, int encryptionLength) {

    verify((AsymmetricAccess) access, encryptionLength, true);
  }

  private void verify(AsymmetricAccess<SignatureBinary, PrivateKey, PublicKey, ?, ?> access, int encryptionLength,
      boolean bidirectional) {

    AsymmetricKeyCreator<PrivateKey, PublicKey, ?> keyCreator = access.newKeyCreator();
    AsymmetricKeyPair keyPair = keyCreator.generateKeyPair();
    verifyKeyPair(keyPair, keyCreator);
    // encryption
    byte[] rawMessage = "Secret message".getBytes(StandardCharsets.UTF_8);
    PublicKey publicKey = keyPair.getPublicKey();
    PrivateKey privateKey = keyPair.getPrivateKey();
    verifyCrypt(access.newEncryptor(publicKey), access.newDecryptor(privateKey), rawMessage, encryptionLength);
    if (bidirectional) {
      verifyCrypt(access.newEncryptorUnsafe(privateKey), access.newDecryptorUnsafe(publicKey), rawMessage,
          encryptionLength);
    }
    // signing
    CryptoBinary data = new CryptoBinary(rawMessage);
    SignatureBinary signature = access.newSigner(privateKey).sign(data, true);
    boolean signatureVerified = access.newVerifier(publicKey).verify(data, signature);
    assertThat(signatureVerified).as("signature verified").isTrue();
  }

  /**
   * @param keyPair the {@link AsymmetricKeyPair} to verify.
   * @param keyCreator the {@link AsymmetricKeyCreator}.
   */
  protected void verifyKeyPair(AsymmetricKeyPair keyPair, AsymmetricKeyCreator keyCreator) {

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
   * @return the expected (maximum) length in bytes of the {@link io.github.mmm.crypto.CryptoBinaryFormat#FORMAT_COMPACT
   *         compact public key data}.
   */
  protected int getPublicKeyCompactLength() {

    return getPublicKeyEncodedLength();
  }

  /**
   * @return the expected (minimum) length in bytes of the {@link io.github.mmm.crypto.CryptoBinaryFormat#FORMAT_COMPACT
   *         compact public key data}.
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
   * @return the expected (maximum) length in bytes of the {@link io.github.mmm.crypto.CryptoBinaryFormat#FORMAT_COMPACT
   *         compact private key data}.
   */
  protected int getPrivateKeyCompactLength() {

    return getPrivateKeyEncodedLength();
  }

  /**
   * @return the expected (minimum) length in bytes of the {@link io.github.mmm.crypto.CryptoBinaryFormat#FORMAT_COMPACT
   *         compact private key data}.
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
   * @param signature the {@link SignatureBinary} to verify.
   * @param minLength the minimum length
   * @param maxLength the maximum length
   */
  protected void verifySignatureLength(SignatureBinary signature, int minLength, int maxLength) {

    if (maxLength > 0) {
      AbstractIntegerAssert<?> length = assertThat(signature.getLength()).as("signature.length");
      if (minLength == maxLength) {
        length.isEqualTo(minLength);
      } else {
        length.isBetween(Integer.valueOf(minLength), Integer.valueOf(maxLength));
      }
    }
  }

  private void verifyCrypt(Encryptor encryptor, Decryptor decryptor, byte[] rawMessage, int encryptionLength) {

    byte[] encryptedMessage = encryptor.crypt(rawMessage, true);
    byte[] decryptedMessage = decryptor.crypt(encryptedMessage, true);
    assertThat(decryptedMessage).isEqualTo(rawMessage);

    if (encryptionLength > 0) {
      assertThat(encryptedMessage).hasSize(encryptionLength);
    }
  }

}
