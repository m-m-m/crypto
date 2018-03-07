package net.sf.mmm.security.api.key;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityGetAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.symmetric.AbstractSecurityGetSymmetricKeyFactory;

/**
 * Abstract interface that combines {@link AbstractSecurityGetAsymmetricKeyFactory} and
 * {@link AbstractSecurityGetSymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetKeyFactory
    extends AbstractSecurityGetAsymmetricKeyFactory, AbstractSecurityGetSymmetricKeyFactory {

}
