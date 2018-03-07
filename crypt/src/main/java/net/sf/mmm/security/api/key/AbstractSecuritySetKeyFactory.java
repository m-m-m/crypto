package net.sf.mmm.security.api.key;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecuritySetAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.symmetric.AbstractSecuritySetSymmetricKeyFactory;

/**
 * Abstract interface that combines {@link AbstractSecuritySetAsymmetricKeyFactory} and
 * {@link AbstractSecuritySetSymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetKeyFactory extends AbstractSecurityGetKeyFactory,
    AbstractSecuritySetAsymmetricKeyFactory, AbstractSecuritySetSymmetricKeyFactory {

}
