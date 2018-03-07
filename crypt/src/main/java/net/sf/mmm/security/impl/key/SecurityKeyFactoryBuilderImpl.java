package net.sf.mmm.security.impl.key;

import net.sf.mmm.security.api.key.SecurityKeyFactoryBuilder;
import net.sf.mmm.security.impl.key.asymmetric.SecurityAsymmetricKeyFactoryBuilderImpl;
import net.sf.mmm.security.impl.key.symmetric.SecuritySymmetricKeyFactoryBuilderImpl;

/**
 * Implementation of {@link SecurityKeyFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityKeyFactoryBuilderImpl
    extends SecurityKeyFactoryBuilder, SecurityAsymmetricKeyFactoryBuilderImpl, SecuritySymmetricKeyFactoryBuilderImpl {

}
