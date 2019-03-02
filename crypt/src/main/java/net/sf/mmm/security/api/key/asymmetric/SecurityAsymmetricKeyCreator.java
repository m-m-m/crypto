package net.sf.mmm.security.api.key.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.util.datatype.api.Binary;
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
   * @param privateKeyBytes the {@link SecurityPrivateKey} as raw {@code byte} array.
   * @return the deserialized {@link SecurityPrivateKey}.
   */
  SecurityPrivateKey deserializePrivateKey(byte[] privateKeyBytes);

  /**
   * @param privateKeyBase64 the {@link SecurityPrivateKey} in {@link BinaryType#getBase64() base64 representation}.
   * @return the deserialized {@link SecurityPrivateKey}.
   */
  default SecurityPrivateKey deserializePrivateKey(String privateKeyBase64) {

    return deserializePrivateKey(BinaryType.parseBase64(privateKeyBase64));
  }

  /**
   * @param privateKey the raw {@link PrivateKey}.
   * @return the wrapped {@link SecurityPrivateKey}.
   */
  SecurityPrivateKey createPrivateKey(PrivateKey privateKey);

  /**
   * @param publicKeyBytes the {@link SecurityPublicKey} as raw {@code byte} array.
   * @return the deserialized {@link SecurityPublicKey}.
   */
  SecurityPublicKey deserializePublicKey(byte[] publicKeyBytes);

  /**
   * @param publicKeyBase64 the {@link SecurityPublicKey} in {@link BinaryType#getBase64() base64 representation}.
   * @return the deserialized {@link SecurityPublicKey}.
   */
  default SecurityPublicKey deserializePublicKey(String publicKeyBase64) {

    return deserializePublicKey(BinaryType.parseBase64(publicKeyBase64));
  }

  /**
   * @param publicKey the raw {@link PublicKey}.
   * @return the wrapped {@link SecurityPublicKey}.
   */
  SecurityPublicKey createPublicKey(PublicKey publicKey);

  /**
   * @param privateKeyBase64 the {@link SecurityPrivateKey} in {@link BinaryType#getBase64() base64 representation}.
   * @param publicKeyBase64 the {@link SecurityPublicKey} in {@link BinaryType#getBase64() base64 representation}.
   * @return the deserialized {@link SecurityAsymmetricKeyPair}.
   */
  default SecurityAsymmetricKeyPair deserializeKeyPair(String privateKeyBase64, String publicKeyBase64) {

    SecurityPrivateKey privateKey = deserializePrivateKey(privateKeyBase64);
    SecurityPublicKey publicKey = deserializePublicKey(publicKeyBase64);
    return createKeyPair(privateKey, publicKey);
  }

  /**
   * @param privateKeyBytes the {@link SecurityPrivateKey} in {@link BinaryType#getHex() hex representation}.
   * @param publicKeyBytes the {@link SecurityPublicKey} in {@link BinaryType#getHex() hex representation}.
   * @return the deserialized {@link SecurityAsymmetricKeyPair}.
   */
  default SecurityAsymmetricKeyPair deserializeKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {

    SecurityPrivateKey privateKey = deserializePrivateKey(privateKeyBytes);
    SecurityPublicKey publicKey = deserializePublicKey(publicKeyBytes);
    return createKeyPair(privateKey, publicKey);
  }

  /**
   * @param privateKey the {@link SecurityPrivateKey}.
   * @param publicKey the {@link SecurityPublicKey}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  SecurityAsymmetricKeyPair createKeyPair(SecurityPrivateKey privateKey, SecurityPublicKey publicKey);

  /**
   * @param keyPairBytes the {@link SecurityAsymmetricKeyPair} in its {@link SecurityAsymmetricKeyPair#asBinary() binary
   *        form} as {@link Binary#getData() raw byte array}.
   * @return the deserialized {@link SecurityAsymmetricKeyPair}.
   */
  SecurityAsymmetricKeyPair deserializeKeyPair(byte[] keyPairBytes);

  /**
   * @param keyPairBase64 the {@link SecurityAsymmetricKeyPair} in its {@link SecurityAsymmetricKeyPair#asBinary()
   *        binary form} as {@link Binary#getBase64() base64 representation}.
   * @return the deserialized {@link SecurityAsymmetricKeyPair}.
   */
  default SecurityAsymmetricKeyPair deserializeKeyPair(String keyPairBase64) {

    return deserializeKeyPair(BinaryType.parseBase64(keyPairBase64));
  }

}
