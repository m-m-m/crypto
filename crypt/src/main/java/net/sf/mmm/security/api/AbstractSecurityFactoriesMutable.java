package net.sf.mmm.security.api;

import net.sf.mmm.security.api.crypt.AbstractSecuritySetCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.hash.AbstractSecuritySetHashFactory;
import net.sf.mmm.security.api.key.AbstractSecuritySetKeyFactory;
import net.sf.mmm.security.api.random.AbstractSecuritySetRandomFactory;
import net.sf.mmm.security.api.sign.AbstractSecuritySetSignatureFactory;

/**
 * Extends {@link AbstractSecurityFactories} with ability to modify the {@link AbstractSecurityFactory factories} via
 * setter methods.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecurityFactoriesMutable extends AbstractSecurityFactories, AbstractSecuritySetRandomFactory,
    AbstractSecuritySetHashFactory, AbstractSecuritySetCryptorFactory<SecurityCryptorFactory>,
    AbstractSecuritySetSignatureFactory, AbstractSecuritySetKeyFactory {

}
