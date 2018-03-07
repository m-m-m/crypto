package net.sf.mmm.security.api.crypt.asymmetric;

/**
 * Extends {@link AbstractSecurityAsymmetricCryptorBuilder} for
 * {@link SecurityAsymmetricCryptorFactoryBidirectional asymmetric bidirectional cryptography}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 * @param <B> type of the returned builder.
 */
public abstract class AbstractSecurityAsymmetricCryptorBuilderBidirectional<B extends AbstractSecurityAsymmetricCryptorBuilderBidirectional<B>>
    extends AbstractSecurityAsymmetricCryptorBuilder<SecurityAsymmetricCryptorFactoryBidirectional, B> {

  private SecurityAsymmetricCryptorFactoryBidirectional factory;

  @Override
  protected abstract SecurityAsymmetricCryptorConfigBidirectional getCryptorConfig();

  @Override
  public SecurityAsymmetricCryptorFactoryBidirectional getCryptorFactory() {

    if (this.factory == null) {
      this.factory = getFactoryBuilder().crypt(getCryptorConfig());
    }
    return this.factory;
  }

}
