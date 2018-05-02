/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import org.assertj.core.api.AbstractIntegerAssert;
import org.assertj.core.api.Assertions;

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

/**
 * Abstract test class for {@link AbstractSecurityAsymmetricCryptorBuilder}.
 */
public abstract class SecurityAsymmetricCryptorBuilderTest extends Assertions {

  /**
   * @param builder the {@link AbstractSecurityAsymmetricCryptorBuilderPublicPrivate} to test.
   */
  protected void verifyPublicPrivate(AbstractSecurityAsymmetricCryptorBuilderPublicPrivate<?> builder) {

    verify(builder, false, true);
  }

  /**
   * @param builder the {@link AbstractSecurityAsymmetricCryptorBuilderPrivatePublic} to test.
   */
  protected void verifyPrivatePublic(AbstractSecurityAsymmetricCryptorBuilderPrivatePublic<?> builder) {

    verify(builder, true, false);
  }

  /**
   * @param builder the {@link AbstractSecurityAsymmetricCryptorBuilderBidirectional} to test.
   */
  protected void verifyBidirectional(AbstractSecurityAsymmetricCryptorBuilderBidirectional<?> builder) {

    verify(builder, true, true);
  }

  private void verify(AbstractSecurityAsymmetricCryptorBuilder<?, ?> builder, boolean privatePublic, boolean publicPrivate) {

    try {
      SecurityAsymmetricKeyPair keyPair = builder.generateKeyPair();
      verifyKeyPair(keyPair, builder.getAsymmetricKeyFactory().newKeyCreator());
      // encryption
      SecurityAsymmetricCryptorFactory cryptorFactory = builder.crypt();
      byte[] rawMessage = "Secret message".getBytes("UTF-8");
      SecurityPublicKey publicKey = keyPair.getPublicKey();
      SecurityPrivateKey privateKey = keyPair.getPrivateKey();
      if (privatePublic) {
        assertThat(cryptorFactory).isInstanceOf(SecurityAsymmetricCryptorFactoryPrivatePublic.class);
        SecurityAsymmetricCryptorFactoryPrivatePublic f = (SecurityAsymmetricCryptorFactoryPrivatePublic) cryptorFactory;
        verifyCrypt(f.newEncryptor(privateKey), f.newDecryptor(publicKey), rawMessage);
      }
      if (publicPrivate) {
        assertThat(cryptorFactory).isInstanceOf(SecurityAsymmetricCryptorFactoryPublicPrivate.class);
        SecurityAsymmetricCryptorFactoryPublicPrivate f = (SecurityAsymmetricCryptorFactoryPublicPrivate) cryptorFactory;
        verifyCrypt(f.newEncryptor(publicKey), f.newDecryptor(privateKey), rawMessage);
      }
      // signing
      SecurityHash data = new SecurityHash(rawMessage);
      builder.hash(new SecurityHashConfigSha256(2));
      SecuritySignatureFactory signatureFactory = builder.signUsingHashAndCryptor();
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

    SecurityPublicKey publicKey = keyPair.getPublicKey();
    SecurityPrivateKey privateKey = keyPair.getPrivateKey();
    // key de-/serialization
    byte[] publicKeyData = publicKey.getData();
    SecurityPublicKey deserializePublicKey = keyCreator.deserializePublicKey(publicKeyData);
    assertThat(deserializePublicKey).isEqualTo(publicKey);
    assertThat(deserializePublicKey.getKey()).isEqualTo(publicKey.getKey());
    byte[] encoded = publicKey.getKey().getEncoded();
    if (!Arrays.equals(publicKeyData, encoded)) {
      deserializePublicKey = keyCreator.deserializePublicKey(encoded);
      assertThat(deserializePublicKey).isEqualTo(publicKey);
      assertThat(deserializePublicKey.getKey()).isEqualTo(publicKey.getKey());
    }
    byte[] privateKeyData = privateKey.getData();
    SecurityPrivateKey deserializePrivateKey = keyCreator.deserializePrivateKey(privateKeyData);
    assertThat(deserializePrivateKey).isEqualTo(privateKey);
    assertThat(deserializePrivateKey.getKey()).isEqualTo(privateKey.getKey());
    encoded = privateKey.getKey().getEncoded();
    if (!Arrays.equals(privateKeyData, encoded)) {
      deserializePrivateKey = keyCreator.deserializePrivateKey(encoded);
      assertThat(deserializePrivateKey).isEqualTo(privateKey);
      assertThat(deserializePrivateKey.getKey()).isEqualTo(privateKey.getKey());
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

  private void verifyCrypt(SecurityEncryptor encryptor, SecurityDecryptor decryptor, byte[] rawMessage) {

    byte[] encryptedMessage = encryptor.crypt(rawMessage, true);
    byte[] decryptedMessage = decryptor.crypt(encryptedMessage, true);
    assertThat(decryptedMessage).isEqualTo(rawMessage);

    int encryptionLength = getEncryptionLength();
    if (encryptionLength > 0) {
      assertThat(encryptedMessage).hasSize(encryptionLength);
    }
  }

  /**
   * @return the expected length in bytes of the encrypted data from the payload "Secret message".
   */
  protected abstract int getEncryptionLength();

}
