package net.sf.mmm.security.api.crypt;

import java.security.Provider;

import net.sf.mmm.security.api.AbstractSecurityBuilder;
import net.sf.mmm.security.api.AbstractSecurityFactories;
import net.sf.mmm.security.api.AbstractSecurityFactory;
import net.sf.mmm.security.api.SecurityFactoryBuilder;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.hash.SecurityHashFactoryBuilder;
import net.sf.mmm.security.api.provider.SecurityProviderBuilder;
import net.sf.mmm.security.api.sign.AbstractSecuritySignatureFactoryBuilder;
import net.sf.mmm.security.api.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.security.impl.sign.SecuritySignatureFactoryImplWithHash;

/**
 * Abstract base class for quick and short access to cryptor algorithms.
 *
 * @param <C> the type of the {@link SecurityCryptorFactory}.
 * @param <B> this builder itself.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityCryptorBuilder<C extends SecurityCryptorFactory, B extends AbstractSecurityCryptorBuilder<C, B>>
    implements AbstractSecurityGetCryptorFactory<C>, SecurityProviderBuilder<B>, AbstractSecuritySignatureFactoryBuilder, SecurityHashFactoryBuilder {

  private final SecurityFactoryBuilder factoryBuilder;

  /**
   * The constructor.
   */
  public AbstractSecurityCryptorBuilder() {

    super();
    this.factoryBuilder = AbstractSecurityBuilder.getInstance().newFactoryBuilder();
  }

  /**
   * @return the optional {@link SecuritySignatureConfig}.
   */
  protected SecuritySignatureConfig getSignatureConfig() {

    return null;
  }

  /**
   * @return the result of {@link #getCryptorFactory()}.
   */
  public C crypt() {

    return getCryptorFactory();
  }

  @Override
  public SecurityHashFactory hash(SecurityHashConfig configuration) {

    return this.factoryBuilder.hash(configuration);
  }

  /**
   * Same as {@link #hash(SecurityHashConfig)} but returning {@code this} for builder pattern and fluent API.
   *
   * @param configuration the {@link SecurityHashConfig}.
   * @return this.
   */
  public B withHash(SecurityHashConfig configuration) {

    hash(configuration);
    return self();
  }

  @Override
  public SecuritySignatureFactory signUsingCryptor(SecurityHashFactory hashFactory) {

    SecuritySignatureConfig signatureConfig = getSignatureConfig();
    if (signatureConfig == null) {
      getCryptorFactory();
      return this.factoryBuilder.signUsingCryptor(hashFactory);
    } else {
      SecuritySignatureFactory signatureFactory = this.factoryBuilder.sign(signatureConfig);
      return new SecuritySignatureFactoryImplWithHash(signatureFactory, hashFactory);
    }
  }

  @Override
  public SecuritySignatureFactory signUsingHashAndCryptor() {

    return signUsingCryptor(this.factoryBuilder.getHashFactoryRequired());
  }

  @Override
  public B provider() {

    this.factoryBuilder.provider();
    return self();
  }

  @Override
  public B provider(String name) {

    this.factoryBuilder.provider(name);
    return self();
  }

  @Override
  public B provider(Provider provider) {

    this.factoryBuilder.provider(provider);
    return self();
  }

  /**
   * @return this builder itself.
   */
  @SuppressWarnings("unchecked")
  protected B self() {

    return (B) this;
  }

  /**
   * @return the {@link SecurityFactoryBuilder}.
   */
  protected SecurityFactoryBuilder getFactoryBuilder() {

    return this.factoryBuilder;
  }

  /**
   * @return the {@link AbstractSecurityFactories} that gives access to the configured {@link AbstractSecurityFactory
   *         factories}.
   */
  public AbstractSecurityFactories getFactories() {

    getCryptorFactory();
    return this.factoryBuilder;
  }

  /**
   * @return the {@link SecurityCryptorConfig}.
   */
  protected abstract SecurityCryptorConfig<?> getCryptorConfig();

}
