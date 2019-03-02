package net.sf.mmm.security.api.key.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface for factory to create instances of {@link SecurityAsymmetricKeyPair}, {@link SecurityPrivateKey}, and
 * {@link SecurityPublicKey}. It only provides low-level wrapping functionality. For higher level usage see
 * {@link SecurityAsymmetricKeyFactory}.
 *
 * @param <PR> type of unwrapped {@link PrivateKey}.
 * @param <PU> type of unwrapped {@link PublicKey}.
 * @param <PRIV> type of wrapped {@link SecurityPrivateKey}.
 * @param <PUB> type of wrapped {@link SecurityPublicKey}.
 * @param <PAIR> type of {@link SecurityAsymmetricKeyPair}.
 * @since 1.0.0
 */
public abstract class AbstractSecurityAsymmetricKeyPairFactory<PR extends PrivateKey, PU extends PublicKey, PRIV extends AbstractSecurityPrivateKey<PR>, PUB extends AbstractSecurityPublicKey<PU>, PAIR extends AbstractSecurityAsymmetricKeyPair<PRIV, PUB>>
    implements SecurityAsymmetricKeyPairFactory<PR, PU, PRIV, PUB, PAIR> {

}
