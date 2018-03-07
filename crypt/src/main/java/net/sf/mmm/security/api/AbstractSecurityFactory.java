package net.sf.mmm.security.api;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;

/**
 * Abstract interface for any factory of this security library. All such factories are thread-safe and represent a
 * specific configuration (see {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig}) based on an
 * {@link #getAlgorithm() algorithm} that shall also be reflected by its {@link #toString() string representation}.
 *
 * @see net.sf.mmm.security.api.random.SecurityRandomFactory
 * @see net.sf.mmm.security.api.hash.SecurityHashFactory
 * @see net.sf.mmm.security.api.crypt.SecurityCryptorFactory
 * @see net.sf.mmm.security.api.sign.SecuritySignatureFactory
 * @see net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory
 * @see net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactory
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityFactory extends SecurityAlgorithm {

  /**
   * @return the type of this factory that may be used for debugging or error messages.
   */
  String getType();

}
