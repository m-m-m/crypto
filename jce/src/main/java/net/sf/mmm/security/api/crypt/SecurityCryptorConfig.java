package net.sf.mmm.security.api.crypt;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * Class of an {@link SecurityAlgorithmConfig algorithm configuration} for
 * {@link SecurityEncryptor#crypt(byte[], boolean) encryption} and {@link SecurityDecryptor#crypt(byte[], boolean)
 * decryption}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCryptorConfig extends SecurityAlgorithmConfig implements AbstractSecurityGetNonceSize {

  private final int nonceSize;

  /**
   * The constructor.
   *
   * @param algorithm the {@link javax.crypto.Cipher#getAlgorithm() algorithm} for encryption and decryption.
   * @param provider the {@link SecurityProvider}.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   */
  public SecurityCryptorConfig(String algorithm, SecurityProvider provider, int nonceSize) {

    super(algorithm, provider);
    this.nonceSize = nonceSize;
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
