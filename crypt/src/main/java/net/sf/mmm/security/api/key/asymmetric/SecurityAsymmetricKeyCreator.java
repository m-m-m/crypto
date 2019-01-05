package net.sf.mmm.security.api.key.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.util.datatype.api.BinaryType;

/**
 * Extends {@link SecurityKeyCreator} for dealing with asymmetric cryptographic keys.
 *
 * @see #createPrivateKey(PrivateKey)
 * @see #createPublicKey(PublicKey)
 * @see #deserializeKeyPair(String, String)
 * @see #deserializeKeyPair(byte[], byte[])
 * @see SecurityKeyCreator
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeyCreator extends SecurityKeyCreator, SecurityAsymmetricKeyConstants {

  /**
   * @return a new {@link SecurityAsymmetricKeyPair} of {@link SecurityAsymmetricKeyPair#getPrivateKey() private} and
   *         {@link SecurityAsymmetricKeyPair#getPublicKey() public} key for the underlying cryptographic algorithm.
   */
  SecurityAsymmetricKeyPair generateKeyPair();

  /**
   * @param privateKey the {@link SecurityPrivateKey} as raw {@code byte} array.
   * @return the deserialized {@link SecurityPrivateKey}.
   */
  SecurityPrivateKey deserializePrivateKey(byte[] privateKey);

  /**
   * @param privateKey the {@link SecurityPrivateKey} in {@link BinaryType#getBase64() base64 representation}.
   * @return the deserialized {@link SecurityPrivateKey}.
   */
  default SecurityPrivateKey deserializePrivateKey(String privateKey) {

    return deserializePrivateKey(BinaryType.parseBase64(privateKey));
  }

  /**
   * @param privateKey the raw {@link PrivateKey}.
   * @return the wrapped {@link SecurityPrivateKey}.
   */
  default SecurityPrivateKey createPrivateKey(PrivateKey privateKey) {

    return new SecurityPrivateKeyGeneric(privateKey);
  }

  /**
   * @param publicKey the {@link SecurityPublicKey} as raw {@code byte} array.
   * @return the deserialized {@link SecurityPublicKey}.
   */
  SecurityPublicKey deserializePublicKey(byte[] publicKey);

  /**
   * @param publicKey the {@link SecurityPublicKey} in {@link BinaryType#getBase64() base64 representation}.
   * @return the deserialized {@link SecurityPublicKey}.
   */
  default SecurityPublicKey deserializePublicKey(String publicKey) {

    return deserializePublicKey(BinaryType.parseBase64(publicKey));
  }

  /**
   * @param publicKey the raw {@link PublicKey}.
   * @return the wrapped {@link SecurityPublicKey}.
   */
  default SecurityPublicKey createPublicKey(PublicKey publicKey) {

    return new SecurityPublicKeyGeneric(publicKey);
  }

  /**
   * @param privateKey the {@link SecurityPrivateKey} in {@link BinaryType#getBase64() base64 representation}.
   * @param publicKey the {@link SecurityPublicKey} in {@link BinaryType#getBase64() base64 representation}.
   * @return the deserialized {@link SecurityAsymmetricKeyPair}.
   */
  default SecurityAsymmetricKeyPair deserializeKeyPair(String privateKey, String publicKey) {

    return new SecurityAsymmetricKeyPairGeneric(deserializePrivateKey(privateKey), deserializePublicKey(publicKey));
  }

  /**
   * @param privateKey the {@link SecurityPrivateKey} in {@link BinaryType#getHex() hex representation}.
   * @param publicKey the {@link SecurityPublicKey} in {@link BinaryType#getHex() hex representation}.
   * @return the deserialized {@link SecurityAsymmetricKeyPair}.
   */
  default SecurityAsymmetricKeyPair deserializeKeyPair(byte[] privateKey, byte[] publicKey) {

    return new SecurityAsymmetricKeyPairGeneric(deserializePrivateKey(privateKey), deserializePublicKey(publicKey));
  }

}
