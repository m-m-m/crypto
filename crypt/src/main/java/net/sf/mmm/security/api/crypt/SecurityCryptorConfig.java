package net.sf.mmm.security.api.crypt;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;
import net.sf.mmm.security.api.key.SecurityKeyConfig;

/**
 * Class of an {@link SecurityAlgorithmConfig algorithm configuration} for
 * {@link SecurityEncryptor#crypt(byte[], boolean) encryption} and {@link SecurityDecryptor#crypt(byte[], boolean)
 * decryption}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 * @param <K> type of {@link #getKeyAlgorithmConfig()}.
 */
public class SecurityCryptorConfig<K extends SecurityKeyConfig> extends SecurityAlgorithmConfig
    implements AbstractSecurityGetNonceSize {

  private final K keyAlgorithmConfig;

  private final int nonceSize;

  /**
   * The constructor.
   *
   * @param algorithm the {@link javax.crypto.Cipher#getAlgorithm() algorithm} for encryption and decryption.
   * @param keyAlgorithmConfig the corresponding {@link SecurityKeyConfig}.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   */
  public SecurityCryptorConfig(String algorithm, K keyAlgorithmConfig, int nonceSize) {
    super(algorithm);
    this.keyAlgorithmConfig = keyAlgorithmConfig;
    this.nonceSize = nonceSize;
  }

  /**
   * @return the {@link SecurityKeyConfig} corresponding to the {@link #getAlgorithm() algorithm} for
   *         encryption and decryption.
   */
  public K getKeyAlgorithmConfig() {

    return this.keyAlgorithmConfig;
  }

  /**
   * This method returns {@code false} by default. You may override this method to create a random nonce individually
   * but only if you know exactly what you are doing and what are the details about the cryptographic algorithm.
   *
   * @return {@code true} if the {@link #getNonceSize() nonce} should be created individually from
   *         {@link java.security.SecureRandom}, {@code false} to get from {@link javax.crypto.Cipher#getIV()
   *         initialization vector}.
   */
  public boolean isCreateRandomNonce() {

    return false;
  }

  @Override
  public final int getNonceSize() {

    return this.nonceSize;
  }

}
