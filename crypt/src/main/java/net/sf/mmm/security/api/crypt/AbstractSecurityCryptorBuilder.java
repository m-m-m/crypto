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
import net.sf.mmm.security.api.sign.AbstractSecurityGetSignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;

/**
 * Abstract base class for quick and short access to cryptor algorithms.
 *
 * @param <C> the type of the {@link SecurityCryptorFactory}.
 * @param <B> this builder itself.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityCryptorBuilder<C extends SecurityCryptorFactory, B extends AbstractSecurityCryptorBuilder<C, B>>
    implements AbstractSecurityGetCryptorFactory<C>, AbstractSecurityGetSignatureFactory, SecurityProviderBuilder<B>,
    SecurityHashFactoryBuilder {

  private final SecurityFactoryBuilder factoryBuilder;

  private SecurityHashConfig hashConfig;

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
  protected abstract SecuritySignatureConfig getSignatureConfig();

  /**
   * @return the result of {@link #getCryptorFactory()}.
   */
  public C crypt() {

    return getCryptorFactory();
  }

  @Override
  public SecurityHashFactory hash(SecurityHashConfig configuration) {

    this.hashConfig = configuration;
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

  /**
   * @return the {@link SecurityHashConfig} or {@code null} if not yet {@link #hash(SecurityHashConfig) set}.
   */
  protected SecurityHashConfig getHashConfig() {

    return this.hashConfig;
  }

  /**
   * @return the result of {@link #getSignatureFactory()}.
   */
  public SecuritySignatureFactory sign() {

    return getSignatureFactory();
  }

  @Override
  public SecuritySignatureFactory getSignatureFactory() {

    SecuritySignatureFactory signatureFactory = this.factoryBuilder.getSignatureFactory();
    if (signatureFactory == null) {
      signatureFactory = this.factoryBuilder.sign(getSignatureConfig());
    }
    return signatureFactory;
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
