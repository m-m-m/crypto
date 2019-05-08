package net.sf.mmm.security.api;

/**
 * Abstract interface for any factory of this security library. All such factories are thread-safe and represent a
 * specific configuration (see {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig}).
 *
 * @see net.sf.mmm.security.api.random.SecurityRandomFactory
 * @see net.sf.mmm.security.api.hash.SecurityHashFactory
 * @see net.sf.mmm.security.api.crypt.SecurityCryptorFactory
 * @see net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureProcessorFactory
 * @see net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyFactory
 * @see net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyFactory
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityFactory {

}
