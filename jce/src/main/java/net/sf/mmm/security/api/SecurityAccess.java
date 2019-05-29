package net.sf.mmm.security.api;

/**
 * Implementations (non-abstract sub-classes) of {@link SecurityAccess} represent the main entry point for the API
 * provided by this security library. All implementations act as factory for according security objects to create keys,
 * encryptors/decryptors, signatures, hashes, or random.
 *
 * @see net.sf.mmm.security.api.asymmetric.access.SecurityAccessAsymmetric
 * @see net.sf.mmm.security.api.symmetric.access.SecurityAccessSymmetric
 *
 * @since 1.0.0
 */
public abstract class SecurityAccess {

}
