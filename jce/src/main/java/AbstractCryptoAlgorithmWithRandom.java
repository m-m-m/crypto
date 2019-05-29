

import java.security.SecureRandom;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithmImpl;
import net.sf.mmm.crypto.provider.SecurityProvider;
import net.sf.mmm.crypto.random.RandomFactory;
import net.sf.mmm.crypto.random.RandomFactoryImpl;

/**
 * Extends {@link CryptoAlgorithmImpl} with ability to create
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractCryptoAlgorithmWithRandom extends AbstractCryptoAlgorithmWithProvider {

  private final RandomFactory randomFactory;

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   * @param randomFactory the {@link RandomFactory} to use.
   */
  public AbstractCryptoAlgorithmWithRandom(SecurityProvider provider, RandomFactory randomFactory) {

    super(provider);
    if (randomFactory == null) {
      this.randomFactory = RandomFactoryImpl.ofStrong();
    } else {
      this.randomFactory = randomFactory;
    }
  }

  /**
   * @return the {@link RandomFactory}.
   */
  protected RandomFactory getRandomFactory() {

    return this.randomFactory;
  }

  /**
   * @return a new {@link SecureRandom}.
   * @see RandomFactory#newSecureRandom()
   */
  protected SecureRandom createSecureRandom() {

    return this.randomFactory.newSecureRandom();
  }
}
