package net.sf.mmm.security.api.algorithm;

/**
 * The abstract interface for any object that is based on a security {@link #getAlgorithm() algorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityAlgorithm {

  /**
   * @return the name of the underlying algorithm (e.g. "RSA", "NONEwithECDSA", etc.).
   *
   * @see java.security.Key#getAlgorithm()
   * @see java.security.Signature#getAlgorithm()
   * @see java.security.MessageDigest#getAlgorithm()
   * @see java.security.SecureRandom#getAlgorithm()
   * @see javax.crypto.Cipher#getAlgorithm()
   */
  String getAlgorithm();

}
