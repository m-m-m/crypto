

import java.security.Provider;

import net.sf.mmm.crypto.algorithm.AbstractSecurityAlgorithm;
import net.sf.mmm.crypto.algorithm.CryptoAlgorithm;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * The abstract base implementation of {@link CryptoAlgorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractCryptoAlgorithmWithProvider extends AbstractSecurityAlgorithm {

  /** The {@link SecurityProvider}. */
  protected final SecurityProvider provider;

  /**
   * The constructor.
   *
   * @param provider the optional security {@link Provider}.
   */
  public AbstractCryptoAlgorithmWithProvider(SecurityProvider provider) {

    super();
    if (provider == null) {
      this.provider = SecurityProvider.DEFAULT;
    } else {
      this.provider = provider;
    }
  }

  /**
   * @return the {@link SecurityProvider}.
   */
  public SecurityProvider getProvider() {

    return this.provider;
  }

}
