package net.sf.mmm.security.api.key.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.Supplier;

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
public interface SecurityAsymmetricKeyPairFactory<PR extends PrivateKey, PU extends PublicKey, PRIV extends SecurityPrivateKey, PUB extends SecurityPublicKey, PAIR extends AbstractSecurityAsymmetricKeyPair<PRIV, PUB>> {

  /**
   * @return {@link Class} reflecting the {@link SecurityPrivateKey} implementation.
   */
  Class<PRIV> getSecurityPrivateKeyClass();

  /**
   * @return {@link Class} reflecting the {@link SecurityPublicKey} implementation.
   */
  Class<PUB> getSecurityPublicKeyClass();

  /**
   * @return {@link Class} reflecting the {@link SecurityAsymmetricKeyPair} implementation.
   */
  Class<PAIR> getSecurityAsymmetricKeyPairClass();

  /**
   * @param privateKey the {@link PrivateKey}.
   * @return the wrapped {@link SecurityPrivateKey}.
   */
  PRIV createPrivateKey(PR privateKey);

  /**
   * @param data the {@link SecurityPrivateKey#getData() binary data} of the {@link SecurityPrivateKey}.
   * @param keySupplier the {@link Supplier} of the {@link PrivateKey}.
   * @return the wrapped {@link SecurityPrivateKey}.
   */
  PRIV createPrivateKey(byte data[], Supplier<PR> keySupplier);

  /**
   * @param publicKey the {@link PublicKey}.
   * @return the wrapped {@link SecurityPublicKey}.
   */
  PUB createPublicKey(PU publicKey);

  /**
   * @param data the {@link SecurityPublicKey#getData() binary data} of the {@link SecurityPublicKey}.
   * @param keySupplier the {@link Supplier} of the {@link PublicKey}.
   * @return the wrapped {@link SecurityPublicKey}.
   */
  PUB createPublicKey(byte data[], Supplier<PU> keySupplier);

  /**
   * @param privateKey the {@link SecurityPrivateKey}.
   * @param publicKey the corresponding {@link SecurityPublicKey}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  PAIR createKeyPair(PRIV privateKey, PUB publicKey);

  /**
   * @param privateKey the {@link PrivateKey}.
   * @param publicKey the corresponding {@link PublicKey}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  default PAIR createKeyPair(PR privateKey, PU publicKey) {

    return createKeyPair(createPrivateKey(privateKey), createPublicKey(publicKey));
  }

  /**
   * @param privateKey the {@link SecurityPrivateKey} to convert.
   * @return the casted or converted {@link SecurityPrivateKey}.
   */
  @SuppressWarnings("unchecked")
  default PRIV convert(SecurityPrivateKey privateKey) {

    if (privateKey.getClass().equals(getSecurityPrivateKeyClass())) {
      return (PRIV) privateKey;
    } else {
      return createPrivateKey((PR) privateKey.getKey());
    }
  }

  /**
   * @param publicKey the {@link SecurityPublicKey} to convert.
   * @return the casted or converted {@link SecurityPublicKey}.
   */
  @SuppressWarnings("unchecked")
  default PUB convert(SecurityPublicKey publicKey) {

    if (publicKey.getClass().equals(getSecurityPublicKeyClass())) {
      return (PUB) publicKey;
    } else {
      return createPublicKey((PU) publicKey.getKey());
    }
  }

  /**
   * @param keyPair the {@link SecurityAsymmetricKeyPair} to convert.
   * @return the casted or converted {@link SecurityAsymmetricKeyPair}.
   */
  @SuppressWarnings("unchecked")
  default PAIR convert(SecurityAsymmetricKeyPair keyPair) {

    if (keyPair.getClass().equals(getSecurityAsymmetricKeyPairClass())) {
      return (PAIR) keyPair;
    } else {
      return createKeyPair(convert(keyPair.getPrivateKey()), convert(keyPair.getPublicKey()));
    }
  }

}
