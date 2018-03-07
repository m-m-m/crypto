package net.sf.mmm.security.api.key;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;

/**
 * Abstract interface for dealing with cryptographic keys. As symmetric and asymmetric key creation are so different
 * there is no common method here. This might change in the future.
 *
 * @see net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator
 * @see net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyCreator
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityKeyCreator extends SecurityAlgorithm {

}
