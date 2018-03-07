package net.sf.mmm.security.api.key.symmetric;

import net.sf.mmm.security.api.key.symmetric.spec.SecuritySymmetricKeySpecFactoryImplPbe;

/**
 * {@link SecuritySymmetricKeyConfig} for PBE (Password Based Encryption).
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricKeyConfigPbe extends SecuritySymmetricKeyConfig {

  private static final byte[] SALT = new byte[] { (byte) 0x0fc, (byte) 0x007, (byte) 0x0cf, (byte) 0x01c, (byte) 0x003,
  (byte) 0x00b, (byte) 0x0ff, (byte) 0x020, (byte) 0x021, (byte) 0x0aa, (byte) 0x027, (byte) 0x0b3, (byte) 0x091,
  (byte) 0x0e6, (byte) 0x0c5, (byte) 0x069, (byte) 0x0ee, (byte) 0x08b, (byte) 0x017, (byte) 0x032 };

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecuritySymmetricKeyConfigPbe(String algorithm, int keyLength) {
    this(algorithm, keyLength, 65536, SALT);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   * @param iterationCount the
   *        {@link net.sf.mmm.security.api.AbstractSecurityGetIterationCount#getIterationCount()
   *        iteration count}.
   */
  public SecuritySymmetricKeyConfigPbe(String algorithm, int keyLength, int iterationCount) {
    this(algorithm, keyLength, iterationCount, SALT);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   * @param iterationCount the
   *        {@link net.sf.mmm.security.api.AbstractSecurityGetIterationCount#getIterationCount()
   *        iteration count}.
   * @param salt the {@link javax.crypto.spec.PBEKeySpec#getSalt() salt}.
   */
  public SecuritySymmetricKeyConfigPbe(String algorithm, int keyLength, int iterationCount, byte[] salt) {
    super(algorithm, keyLength, new SecuritySymmetricKeySpecFactoryImplPbe(salt, iterationCount, keyLength));
  }

}
