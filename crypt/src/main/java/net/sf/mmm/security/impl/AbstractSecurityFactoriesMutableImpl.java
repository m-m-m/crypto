package net.sf.mmm.security.impl;

import java.security.Provider;
import java.util.Objects;

import net.sf.mmm.security.api.AbstractSecurityFactoriesMutable;
import net.sf.mmm.security.api.AbstractSecurityFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactory;
import net.sf.mmm.security.api.provider.AbstractSecuritySetProvider;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;

/**
 * Implementation of {@link AbstractSecurityFactoriesMutable}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class AbstractSecurityFactoriesMutableImpl
    implements AbstractSecurityFactoriesMutable, AbstractSecuritySetProvider {

  private Provider provider;

  private SecurityRandomFactory randomFactory;

  private SecurityHashFactory hashFactory;

  private SecurityCryptorFactory cryptorFactory;

  private SecuritySignatureFactory signatureFactory;

  private SecurityAsymmetricKeyFactory asymmetricKeyFactory;

  private SecuritySymmetricKeyFactory symmetricKeyFactory;

  /**
   * The constructor.
   */
  public AbstractSecurityFactoriesMutableImpl() {

    super();
  }

  @Override
  public Provider getProvider() {

    return this.provider;
  }

  @Override
  public void setProvider(Provider provider) {

    this.provider = provider;
  }

  @Override
  public SecurityRandomFactory getRandomFactory() {

    return this.randomFactory;
  }

  @Override
  public void setRandomFactory(SecurityRandomFactory factory) {

    this.randomFactory = verifySetFactory(this.randomFactory, factory);
  }

  @Override
  public SecurityHashFactory getHashFactory() {

    return this.hashFactory;
  }

  @Override
  public void setHashFactory(SecurityHashFactory factory) {

    this.hashFactory = verifySetFactory(this.hashFactory, factory);
  }

  @Override
  public SecurityCryptorFactory getCryptorFactory() {

    return this.cryptorFactory;
  }

  @Override
  public void setCryptorFactory(SecurityCryptorFactory factory) {

    this.cryptorFactory = verifySetFactory(this.cryptorFactory, factory);
  }

  @Override
  public SecuritySignatureFactory getSignatureFactory() {

    return this.signatureFactory;
  }

  @Override
  public void setSignatureFactory(SecuritySignatureFactory factory) {

    this.signatureFactory = verifySetFactory(this.signatureFactory, factory);
  }

  @Override
  public SecurityAsymmetricKeyFactory getAsymmetricKeyFactory() {

    return this.asymmetricKeyFactory;
  }

  @Override
  public void setAsymmetricKeyFactory(SecurityAsymmetricKeyFactory factory) {

    this.asymmetricKeyFactory = verifySetFactory(this.asymmetricKeyFactory, factory);
  }

  @Override
  public SecuritySymmetricKeyFactory getSymmetricKeyFactory() {

    return this.symmetricKeyFactory;
  }

  @Override
  public void setSymmetricKeyFactory(SecuritySymmetricKeyFactory factory) {

    this.symmetricKeyFactory = verifySetFactory(this.symmetricKeyFactory, factory);
  }

  /**
   * @return {@code true} to allow setting any of the {@link AbstractSecurityFactory factories} only once, {@code false}
   *         otherwise (for simple setters).
   */
  protected boolean isAllowSetFactoryOnlyOnce() {

    return false;
  }

  /**
   * @param <T> type of the {@link AbstractSecurityFactory factory}.
   * @param existingFactory the existing {@link AbstractSecurityFactory factory} to set.
   * @param newFactory the new value of {@link AbstractSecurityFactory factory} to set.
   * @return the given {@code newFactory}.
   */
  protected <T extends AbstractSecurityFactory> T verifySetFactory(T existingFactory, T newFactory) {

    if (existingFactory != null) {
      if (newFactory == null) {
        Objects.requireNonNull(newFactory, existingFactory.getType());
      }
      if (isAllowSetFactoryOnlyOnce()) {
        throw new IllegalStateException(existingFactory.getType() + " may be set only once!");
      }
    }
    return newFactory;
  }

}
