/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.hash.SecurityHash;
import net.sf.mmm.security.api.hash.SecurityHashConfigSha256;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.sign.SecuritySignature;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;

import org.assertj.core.api.AbstractIntegerAssert;
import org.assertj.core.api.Assertions;

/**
 * Abstract test class for {@link AbstractSecurityAsymmetricCryptorBuilder}.
 */
public abstract class SecurityAsymmetricCryptorBuilderTest extends Assertions {

  /**
   * @param builder the {@link AbstractSecurityAsymmetricCryptorBuilderPrivatePublic} to test.
   */
  protected void verify(AbstractSecurityAsymmetricCryptorBuilder<?> builder, int encryptionLength) {

    verify(builder, encryptionLength, false);
  }

  /**
   * @param builder the {@link AbstractSecurityAsymmetricCryptorBuilderBidirectional} to test.
   */
  protected void verifyBidirectional(AbstractSecurityAsymmetricCryptorBuilder<?> builder, int encryptionLength) {

    verify(builder, encryptionLength, true);
  }

  private void verify(AbstractSecurityAsymmetricCryptorBuilder<?> builder, int encryptionLength, boolean bidirectional) {

    try {
      SecurityAsymmetricKeyPair keyPair = builder.generateKeyPair();
      verifyKeyPair(keyPair, builder.getAsymmetricKeyFactory().newKeyCreator());
      // encryption
      SecurityAsymmetricCryptorFactory cryptorFactory = builder.crypt();
      byte[] rawMessage = "Secret message".getBytes("UTF-8");
      SecurityPublicKey publicKey = keyPair.getPublicKey();
      SecurityPrivateKey privateKey = keyPair.getPrivateKey();
      verifyCrypt(cryptorFactory.newEncryptor(publicKey), cryptorFactory.newDecryptor(privateKey), rawMessage, encryptionLength);
      if (bidirectional) {
        verifyCrypt(cryptorFactory.newEncryptorUnsafe(privateKey.getKey()), cryptorFactory.newDecryptorUnsafe(publicKey.getKey()),
            rawMessage, encryptionLength);
      }
      // signing
      SecurityHash data = new SecurityHash(rawMessage);
      builder.hash(new SecurityHashConfigSha256(2));
      SecuritySignatureFactory signatureFactory = builder.sign();
      SecuritySignature signature = signatureFactory.newSigner(privateKey).signature(data, true);
      boolean signatureVerified = signatureFactory.newVerifier(publicKey).verify(data, signature);
      assertThat(signatureVerified).as("signature verified").isTrue();
      verifySignature(signature);
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * @param keyPair the {@link SecurityAsymmetricKeyPair} to verify.
   * @param keyCreator the {@link SecurityAsymmetricKeyCreator}.
   */
  protected void verifyKeyPair(SecurityAsymmetricKeyPair keyPair, SecurityAsymmetricKeyCreator keyCreator) {

    // verify private key
    SecurityPrivateKey privateKey = keyPair.getPrivateKey();
    byte[] privateKeyData = privateKey.getData();
    assertThat(privateKeyData.length).isBetween(getPrivateKeyCompactMinLength(), getPrivateKeyCompactLength());
    SecurityPrivateKey deserializePrivateKey = keyCreator.deserializePrivateKey(privateKeyData);
    assertThat(deserializePrivateKey).isEqualTo(privateKey);
    assertThat(deserializePrivateKey.getKey()).isEqualTo(privateKey.getKey());
    byte[] encoded = privateKey.getKey().getEncoded();
    assertThat(encoded.length).isBetween(getPrivateKeyEncodedMinLength(), getPrivateKeyEncodedLength());
    if (!Arrays.equals(privateKeyData, encoded)) {
      deserializePrivateKey = keyCreator.deserializePrivateKey(encoded);
      assertThat(deserializePrivateKey).isEqualTo(privateKey);
      assertThat(deserializePrivateKey.getKey()).isEqualTo(privateKey.getKey());
    }

    // verify public key
    SecurityPublicKey publicKey = keyPair.getPublicKey();
    byte[] publicKeyData = publicKey.getData();
    assertThat(publicKeyData.length).isBetween(getPublicKeyCompactMinLength(), getPublicKeyCompactLength());
    SecurityPublicKey deserializePublicKey = keyCreator.deserializePublicKey(publicKeyData);
    assertThat(deserializePublicKey).isEqualTo(publicKey);
    assertThat(deserializePublicKey.getKey()).isEqualTo(publicKey.getKey());
    encoded = publicKey.getKey().getEncoded();
    assertThat(encoded.length).isBetween(getPublicKeyEncodedMinLength(), getPublicKeyEncodedLength());
    if (!Arrays.equals(publicKeyData, encoded)) {
      deserializePublicKey = keyCreator.deserializePublicKey(encoded);
      assertThat(deserializePublicKey).isEqualTo(publicKey);
      assertThat(deserializePublicKey.getKey()).isEqualTo(publicKey.getKey());
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
