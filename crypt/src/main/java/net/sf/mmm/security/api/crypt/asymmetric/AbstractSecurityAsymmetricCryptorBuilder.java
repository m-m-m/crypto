package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.AbstractSecurityFactories;
import net.sf.mmm.security.api.SecurityFactoryBuilder;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.crypt.AbstractSecurityCryptorBuilder;
import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityGetAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;

/**
 * Direct builder for {@link SecurityAlgorithmRsa RSA}.
 *
 * @param <B> type of the returned builder.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityAsymmetricCryptorBuilder<B extends AbstractSecurityAsymmetricCryptorBuilder<B>>
    extends AbstractSecurityCryptorBuilder<SecurityAsymmetricCryptorFactory, B>
    implements AbstractSecurityGetAsymmetricKeyFactory, SecurityAsymmetricKeyFactory {

  private SecurityAsymmetricCryptorFactory cryptorFactory;

  /**
   * The constructor.
   */
  public AbstractSecurityAsymmetricCryptorBuilder() {

    super();
  }

  @Override
  protected abstract SecurityAsymmetricCryptorConfig getCryptorConfig();

  @Override
  public SecurityAsymmetricKeyFactory getAsymmetricKeyFactory() {

    SecurityFactoryBuilder builder = getFactoryBuilder();
    SecurityAsymmetricKeyFactory factory = builder.getAsymmetricKeyFactory();
    if (factory == null) {
      factory = builder.key(getCryptorConfig().getKeyAlgorithmConfig());
    }
    return factory;
  }

  @Override
  public SecurityAsymmetricCryptorFactory getCryptorFactory() {

    if (this.cryptorFactory == null) {
      this.cryptorFactory = getFactoryBuilder().crypt(getCryptorConfig());
    }
    return this.cryptorFactory;
  }

  @Override
  public SecurityAsymmetricKeyCreator newKeyCreator() {

    return getAsymmetricKeyFactory().newKeyCreator();
  }

  /**
   * @return result of {@link #newKeyCreator()}.{@link SecurityAsymmetricKeyCreator#generateKeyPair()
   *         generateKeyPair()}.
   */
  public SecurityAsymmetricKeyPair generateKeyPair() {

    return newKeyCreator().generateKeyPair();
  }

  @Override
  public String getAlgorithm() {

    return getCryptorConfig().getAlgorithm();
  }

  @Override
  public AbstractSecurityFactories getFactories() {

    getAsymmetricKeyFactory();
    return super.getFactories();
  }

}
