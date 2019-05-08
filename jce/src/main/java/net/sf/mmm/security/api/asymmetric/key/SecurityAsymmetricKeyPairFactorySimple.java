package net.sf.mmm.security.api.asymmetric.key;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface for factory to create instances of {@link SecurityAsymmetricKeyPair} from {@link PrivateKey} and
 * {@link PublicKey}. It only provides low-level wrapping functionality. For higher level usage see
 * {@link SecurityAsymmetricKeyCreator}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link SecurityAsymmetricKeyPair}.
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeyPairFactorySimple<PR extends PrivateKey, PU extends PublicKey, PAIR extends SecurityAsymmetricKeyPair<PR, PU>> {

  /**
   * @param privateKey the {@link PrivateKey}.
   * @param publicKey the corresponding {@link PublicKey}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  PAIR createKeyPair(PR privateKey, PU publicKey);

}
