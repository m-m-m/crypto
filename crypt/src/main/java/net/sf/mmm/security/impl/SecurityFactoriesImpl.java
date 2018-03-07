package net.sf.mmm.security.impl;

import net.sf.mmm.security.api.AbstractSecurityFactories;
import net.sf.mmm.security.api.SecurityFactories;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactory;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;

/**
 * Implementation of {@link SecurityFactories}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityFactoriesImpl implements SecurityFactories {

  private final SecurityRandomFactory randomFactory;

  private final SecurityHashFactory hashFactory;

  private final SecurityCryptorFactory cryptorFactory;

  private final SecuritySignatureFactory signatureFactory;

  private final SecurityAsymmetricKeyFactory asymmetricKeyFactory;

  private final SecuritySymmetricKeyFactory symmetricKeyFactory;

  /**
   * The constructor.
   *
   * @param randomFactory - see {@link #getRandomFactory()}.
   * @param hashFactory - see {@link #getHashFactory()}.
   * @param cryptorFactory - see {@link #getCryptorFactory()}.
   * @param signatureFactory - see {@link #getSignatureFactory()}.
   * @param asymmetricKeyFactory - see {@link #getAsymmetricKeyFactory()}.
   * @param symmetricKeyFactory - see {@link #getSymmetricKeyFactory()}.
   */
  public SecurityFactoriesImpl(SecurityRandomFactory randomFactory, SecurityHashFactory hashFactory,
      SecurityCryptorFactory cryptorFactory, SecuritySignatureFactory signatureFactory,
      SecurityAsymmetricKeyFactory asymmetricKeyFactory, SecuritySymmetricKeyFactory symmetricKeyFactory) {

    super();
    this.randomFactory = randomFactory;
    this.hashFactory = hashFactory;
    this.cryptorFactory = cryptorFactory;
    this.signatureFactory = signatureFactory;
    this.asymmetricKeyFactory = asymmetricKeyFactory;
    this.symmetricKeyFactory = symmetricKeyFactory;
  }

  /**
   * The constructor.
   *
   * @param factories an instance of {@link AbstractSecurityFactories} to "copy" from.
   */
  public SecurityFactoriesImpl(AbstractSecurityFactories factories) {

    super();
    this.randomFactory = factories.getRandomFactory();
    this.hashFactory = factories.getHashFactory();
    this.cryptorFactory = factories.getCryptorFactory();
    this.signatureFactory = factories.getSignatureFactory();
    this.asymmetricKeyFactory = factories.getAsymmetricKeyFactory();
    this.symmetricKeyFactory = factories.getSymmetricKeyFactory();
  }

  @Override
  public SecurityRandomFactory getRandomFactory() {

    return this.randomFactory;
  }

  @Override
  public SecurityHashFactory getHashFactory() {

    return this.hashFactory;
  }

  @Override
  public SecurityCryptorFactory getCryptorFactory() {

    return this.cryptorFactory;
  }

  @Override
  public SecurityAsymmetricKeyFactory getAsymmetricKeyFactory() {

    return this.asymmetricKeyFactory;
  }

  @Override
  public SecuritySymmetricKeyFactory getSymmetricKeyFactory() {

    return this.symmetricKeyFactory;
  }

  @Override
  public SecuritySignatureFactory getSignatureFactory() {

    return this.signatureFactory;
  }

}
