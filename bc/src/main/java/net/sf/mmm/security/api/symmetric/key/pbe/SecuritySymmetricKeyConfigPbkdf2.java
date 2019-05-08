package net.sf.mmm.security.api.symmetric.key.pbe;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmPbkdf2;
import net.sf.mmm.security.api.provider.BouncyCastle;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecuritySymmetricKeyConfigPbe} for {@link SecurityAlgorithmPbkdf2}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricKeyConfigPbkdf2 extends SecuritySymmetricKeyConfigPbe implements SecurityAlgorithmPbkdf2 {

  /** {@link SecuritySymmetricKeyConfigPbkdf2} using HMAC with SHA-256 hashing. */
  public static final SecuritySymmetricKeyConfigPbkdf2 PBKDF2_WITH_HMAC_SHA256 = new SecuritySymmetricKeyConfigPbkdf2(
      ALGORITHM_PBKDF2_WITH_HMAC_SHA256, 256);

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecuritySymmetricKeyConfigPbkdf2(String algorithm, int keyLength) {

    super(algorithm, SecurityProvider.of(BouncyCastle.getProvider()), keyLength);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   * @param iterationCount the {@link net.sf.mmm.security.api.AbstractSecurityGetIterationCount#getIterationCount()
   *        iteration count}.
   */
  public SecuritySymmetricKeyConfigPbkdf2(String algorithm, int keyLength, int iterationCount) {

    super(algorithm, keyLength, iterationCount);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   * @param iterationCount the {@link net.sf.mmm.security.api.AbstractSecurityGetIterationCount#getIterationCount()
   *        iteration count}.
   * @param salt the {@link javax.crypto.spec.PBEKeySpec#getSalt() salt}.
   */
  public SecuritySymmetricKeyConfigPbkdf2(String algorithm, int keyLength, int iterationCount, byte[] salt) {

    super(algorithm, SecurityProvider.BC, keyLength, iterationCount, salt);
  }

}
