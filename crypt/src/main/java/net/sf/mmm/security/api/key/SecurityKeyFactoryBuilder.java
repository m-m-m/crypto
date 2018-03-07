package net.sf.mmm.security.api.key;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactoryBuilder;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactoryBuilder;

/**
 * Interface that combines {@link SecurityAsymmetricKeyFactoryBuilder} and {@link SecuritySymmetricKeyFactoryBuilder} to
 * build any {@link net.sf.mmm.security.api.key.SecurityKeyFactory}.
 *
 * @see net.sf.mmm.security.api.SecurityFactoryBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityKeyFactoryBuilder
    extends SecurityAsymmetricKeyFactoryBuilder, SecuritySymmetricKeyFactoryBuilder {

}
