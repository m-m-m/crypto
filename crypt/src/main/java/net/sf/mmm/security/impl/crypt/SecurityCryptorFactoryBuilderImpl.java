package net.sf.mmm.security.impl.crypt;

import net.sf.mmm.security.api.crypt.AbstractSecuritySetCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactoryBuilder;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigBidirectional;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPrivatePublic;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPublicPrivate;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryBidirectional;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPrivatePublic;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPublicPrivate;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorFactory;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;
import net.sf.mmm.security.api.random.AbstractSecurityGetRandomFactory;
import net.sf.mmm.security.impl.crypt.asymmetric.SecurityAsymmetricCryptorFactoryBidirectionalImpl;
import net.sf.mmm.security.impl.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPrivatePublicImpl;
import net.sf.mmm.security.impl.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPublicPrivateImpl;
import net.sf.mmm.security.impl.crypt.symmetric.SecuritySymmetricCryptorFactoryImpl;

/**
 * Implementation of {@link SecurityCryptorFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCryptorFactoryBuilderImpl
    extends SecurityCryptorFactoryBuilder, AbstractSecuritySetCryptorFactory<SecurityCryptorFactory>,
    AbstractSecurityGetProvider, AbstractSecurityGetRandomFactory {

  @Override
  default SecurityCryptorFactory cryptUnsafe(SecurityCryptorConfig<?> configuration) {

    if (configuration instanceof SecuritySymmetricCryptorConfig) {
      return crypt((SecuritySymmetricCryptorConfig) configuration);
    } else if (configuration instanceof SecurityAsymmetricCryptorConfigBidirectional) {
      return crypt((SecurityAsymmetricCryptorConfigBidirectional) configuration);
    } else if (configuration instanceof SecurityAsymmetricCryptorConfigPublicPrivate) {
      return crypt((SecurityAsymmetricCryptorConfigPublicPrivate) configuration);
    } else if (configuration instanceof SecurityAsymmetricCryptorConfigPrivatePublic) {
      return crypt((SecurityAsymmetricCryptorConfigPrivatePublic) configuration);
    } else {
      throw new IllegalArgumentException(configuration.getClass().getName());
    }
  }

  @Override
  default SecurityAsymmetricCryptorFactoryBidirectional crypt(
      SecurityAsymmetricCryptorConfigBidirectional configuration) {

    SecurityAsymmetricCryptorFactoryBidirectional factory = new SecurityAsymmetricCryptorFactoryBidirectionalImpl(
        configuration, getProvider(), getRandomFactoryRequired());
    setCryptorFactory(factory);
    return factory;
  }

  @Override
  default SecurityAsymmetricCryptorFactoryPrivatePublic crypt(
      SecurityAsymmetricCryptorConfigPrivatePublic configuration) {

    SecurityAsymmetricCryptorFactoryPrivatePublic factory = new SecurityAsymmetricCryptorFactoryPrivatePublicImpl(
        configuration, getProvider(), getRandomFactoryRequired());
    setCryptorFactory(factory);
    return factory;
  }

  @Override
  default SecurityAsymmetricCryptorFactoryPublicPrivate crypt(
      SecurityAsymmetricCryptorConfigPublicPrivate configuration) {

    SecurityAsymmetricCryptorFactoryPublicPrivate factory = new SecurityAsymmetricCryptorFactoryPublicPrivateImpl(
        configuration, getProvider(), getRandomFactoryRequired());
    setCryptorFactory(factory);
    return factory;
  }

  @Override
  default SecuritySymmetricCryptorFactory crypt(SecuritySymmetricCryptorConfig configuration) {

    SecuritySymmetricCryptorFactoryImpl factory = new SecuritySymmetricCryptorFactoryImpl(configuration, getProvider(),
        getRandomFactoryRequired());
    setCryptorFactory(factory);
    return factory;
  }

}
