package net.sf.mmm.security.api;

/**
 * Abstract interface for any builder of a {@link AbstractSecurityFactory security factory} of this security library.
 * Each such builder offers one or multiple methods to build a {@link AbstractSecurityFactory security factory} for a
 * given {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig configuration}.
 *
 * @see net.sf.mmm.security.api.random.AbstractSecurityRandomFactoryBuilder
 * @see net.sf.mmm.security.api.hash.SecurityHashFactoryBuilder
 * @see net.sf.mmm.security.api.crypt.SecurityCryptorFactoryBuilder
 * @see net.sf.mmm.security.api.sign.SecuritySignatureFactory
 * @see net.sf.mmm.security.api.key.SecurityKeyFactoryBuilder
 * @see net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactoryBuilder
 * @see net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactoryBuilder
 * @see SecurityFactoryBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityFactoryBuilder {

}
