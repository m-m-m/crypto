package net.sf.mmm.security.api.crypt.asymmetric;

/**
 * Extends {@link AbstractSecurityAsymmetricCryptorBuilder} for {@link SecurityAsymmetricCryptorFactoryBidirectional
 * asymmetric bidirectional cryptography}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 * @param <B> type of the returned builder.
 */
public abstract class AbstractSecurityAsymmetricCryptorBuilderPrivatePublic<B extends AbstractSecurityAsymmetricCryptorBuilderPrivatePublic<B>>
    extends AbstractSecurityAsymmetricCryptorBuilder<SecurityAsymmetricCryptorFactoryPrivatePublic, B> {

  private SecurityAsymmetricCryptorFactoryPrivatePublic factory;

  @Override
  protected abstract SecurityAsymmetricCryptorConfigPrivatePublic getCryptorConfig();

  @Override
  public SecurityAsymmetricCryptorFactoryPrivatePublic getCryptorFactory() {

    if (this.factory == null) {
      this.factory = getFactoryBuilder().crypt(getCryptorConfig());
    }
    return this.factory;
  }

}
