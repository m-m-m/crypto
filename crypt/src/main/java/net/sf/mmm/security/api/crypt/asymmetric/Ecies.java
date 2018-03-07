package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcies;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfigEc;

/**
 * Direct builder for {@link SecurityAlgorithmEcies ECIES}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class Ecies extends AbstractSecurityAsymmetricCryptorBuilderPublicPrivate<Ecies> {

  private final SecurityAsymmetricCryptorConfigEcies config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfigEcies}.
   */
  public Ecies(SecurityAsymmetricCryptorConfigEcies config) {

    super();
    this.config = config;
  }

  @Override
  protected SecurityAsymmetricCryptorConfigEcies getCryptorConfig() {

    return this.config;
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.key.SecurityKeyConfig#getKeyLength() key length} in
   *        bits.
   * @return the according {@link Ecies} instance.
   */
  public static Ecies keyLength(int keyLength) {

    return new Ecies(new SecurityAsymmetricCryptorConfigEcies(new SecurityAsymmetricKeyConfigEc(keyLength)));
  }

  /**
   * @return the result of {@link #keyLength(int) keyLength}(4096).
   */
  public static Ecies keyLength256() {

    return new Ecies(SecurityAsymmetricCryptorConfigEcies.ECIES_256);
  }

}
