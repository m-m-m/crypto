package net.sf.mmm.security.api.key;

/**
 * Interface to {@link #getKeyLength() get} the {@link #getKeyLength() key-length}.
 *
 * @since 1.0.0-beta1
 */
public interface AbstractSecurityGetKeyLength {

  /**
   * @return the length of the key in bits. The bigger the key length the stronger and more secure the encryption but
   *         also the more performance is required for computation. Reasonable values depend on the
   *         {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithm#getAlgorithm() algorithm}: A recent value for
   *         RSA is 4096 bits while for PBKDF2 256 is sufficient. However, recommended and secure values change over
   *         time as computing power is increasing. Therefore you should research the web to find an accurate value.
   */
  int getKeyLength();

}
