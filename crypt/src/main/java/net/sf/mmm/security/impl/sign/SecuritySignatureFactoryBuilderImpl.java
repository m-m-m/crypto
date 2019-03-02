package net.sf.mmm.security.impl.sign;

import net.sf.mmm.security.api.crypt.AbstractSecurityGetCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactory;
import net.sf.mmm.security.api.hash.AbstractSecurityGetHashFactory;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.hash.SecurityHashFactoryBuilder;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;
import net.sf.mmm.security.api.random.AbstractSecurityGetRandomFactory;
import net.sf.mmm.security.api.sign.AbstractSecuritySetSignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureFactoryBuilder;

/**
 * Implementation of {@link SecurityHashFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureFactoryBuilderImpl
    extends SecuritySignatureFactoryBuilder, AbstractSecurityGetProvider, AbstractSecurityGetRandomFactory, AbstractSecurityGetHashFactory,
    AbstractSecurityGetCryptorFactory<SecurityCryptorFactory>, AbstractSecuritySetSignatureFactory {

  @Override
  default SecuritySignatureFactory sign(SecuritySignatureConfig configuration) {

    SecuritySignatureFactoryImpl factory = new SecuritySignatureFactoryImpl(configuration, getProvider(), getRandomFactoryRequired());
    setSignatureFactory(factory);
    return factory;
  }

  @Override
  default SecuritySignatureFactory sign(SecurityHashFactory hashFactory, SecurityAsymmetricCryptorFactory cryptorFactory) {

    SecuritySignatureFactoryImplCryptorWithHash factory = new SecuritySignatureFactoryImplCryptorWithHash(cryptorFactory, hashFactory);
    setSignatureFactory(factory);
    return factory;
  }

  @Override
  default SecuritySignatureFactory sign(SecuritySignatureConfig configuration, SecurityHashFactory hashFactory) {

    SecuritySignatureFactory signatureFactory = new SecuritySignatureFactoryImpl(configuration, getProvider(), getRandomFactoryRequired());
    SecuritySignatureFactoryImplWithHash factory = new SecuritySignatureFactoryImplWithHash(signatureFactory, hashFactory);
    setSignatureFactory(factory);
    return factory;
  }

  @Override
  default SecuritySignatureFactory signUsingHash(SecuritySignatureConfig configuration) {

    SecuritySignatureFactory signatureFactory = new SecuritySignatureFactoryImpl(configuration, getProvider(), getRandomFactoryRequired());
    SecuritySignatureFactoryImplWithHash factory = new SecuritySignatureFactoryImplWithHash(signatureFactory, getHashFactoryRequired());
    setSignatureFactory(factory);
    return factory;
  }

  @Override
  default SecuritySignatureFactory signUsingCryptor(SecurityHashFactory hashFactory) {

    SecurityCryptorFactory cryptorFactory = getCryptorFactoryRequired();
    if (!(cryptorFactory instanceof SecurityAsymmetricCryptorFactory)) {
      throw new IllegalStateException("Illegal cryptor factory " + cryptorFactory.getClass().getName() + " - has to be an instance of "
          + SecurityAsymmetricCryptorFactory.class.getSimpleName() + " in order to be used for signing.");
    }
    return sign(hashFactory, (SecurityAsymmetricCryptorFactory) cryptorFactory);
  }

  @Override
  default SecuritySignatureFactory signUsingHashAndCryptor() {

    return signUsingCryptor(getHashFactoryRequired());
  }

}
