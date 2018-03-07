package net.sf.mmm.security.api.crypt.asymmetric;

/**
 * Extends {@link AbstractSecurityAsymmetricCryptorBuilder} for {@link SecurityAsymmetricCryptorFactoryBidirectional
 * asymmetric bidirectional cryptography}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 * @param <B> type of the returned builder.
 */
public abstract class AbstractSecurityAsymmetricCryptorBuilderPublicPrivate<B extends AbstractSecurityAsymmetricCryptorBuilderPublicPrivate<B>>
    extends AbstractSecurityAsymmetricCryptorBuilder<SecurityAsymmetricCryptorFactoryPublicPrivate, B> {

  private SecurityAsymmetricCryptorFactoryPublicPrivate factory;

  @Override
  protected abstract SecurityAsymmetricCryptorConfigPublicPrivate getCryptorConfig();

  @Override
  public SecurityAsymmetricCryptorFactoryPublicPrivate getCryptorFactory() {

    if (this.factory == null) {
      this.factory = getFactoryBuilder().crypt(getCryptorConfig());
    }
    return this.factory;
  }

}
