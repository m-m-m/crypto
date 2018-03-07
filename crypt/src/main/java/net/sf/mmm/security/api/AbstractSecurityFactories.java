package net.sf.mmm.security.api;

import net.sf.mmm.security.api.crypt.AbstractSecurityGetCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.hash.AbstractSecurityGetHashFactory;
import net.sf.mmm.security.api.key.AbstractSecurityGetKeyFactory;
import net.sf.mmm.security.api.random.AbstractSecurityGetRandomFactory;
import net.sf.mmm.security.api.sign.AbstractSecurityGetSignatureFactory;

/**
 * Abstract interface that gives read access to all {@link AbstractSecurityFactory security factories}.
 *
 * @see SecurityFactoryBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecurityFactories extends AbstractSecurityGetRandomFactory, AbstractSecurityGetHashFactory,
    AbstractSecurityGetCryptorFactory<SecurityCryptorFactory>, AbstractSecurityGetKeyFactory,
    AbstractSecurityGetSignatureFactory {

}
