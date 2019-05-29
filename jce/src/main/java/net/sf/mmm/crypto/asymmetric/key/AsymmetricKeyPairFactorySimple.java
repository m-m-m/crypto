package net.sf.mmm.crypto.asymmetric.key;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface for factory to create instances of {@link AsymmetricKeyPair} from {@link PrivateKey} and
 * {@link PublicKey}. It only provides low-level wrapping functionality. For higher level usage see
 * {@link AsymmetricKeyCreator}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link AsymmetricKeyPair}.
 * @since 1.0.0
 */
public interface AsymmetricKeyPairFactorySimple<PR extends PrivateKey, PU extends PublicKey, PAIR extends AsymmetricKeyPair<PR, PU>> {

  /**
   * @param privateKey the {@link PrivateKey}.
   * @param publicKey the corresponding {@link PublicKey}.
   * @return the {@link AsymmetricKeyPair}.
   */
  PAIR createKeyPair(PR privateKey, PU publicKey);

}
