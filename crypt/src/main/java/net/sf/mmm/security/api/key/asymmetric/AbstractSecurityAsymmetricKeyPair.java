package net.sf.mmm.security.api.key.asymmetric;

import java.util.Objects;

/**
 * Abstract base implementation of {@link SecurityAsymmetricKeyPair}.
 *
 * @param <PRIV> type of {@link #getPrivateKey() private key}.
 * @param <PUB> type of {@link #getPublicKey() public key}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityAsymmetricKeyPair<PRIV extends SecurityPrivateKey, PUB extends SecurityPublicKey>
    implements SecurityAsymmetricKeyPair {

  /** @see #getPrivateKey() */
  protected final PRIV privateKey;

  /** @see #getPublicKey() */
  protected final PUB publicKey;

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public AbstractSecurityAsymmetricKeyPair(PRIV privateKey, PUB publicKey) {

    super();
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  @Override
  public PRIV getPrivateKey() {

    return this.privateKey;
  }

  @Override
  public PUB getPublicKey() {

    return this.publicKey;
  }

  @Override
  public int hashCode() {

    return Objects.hash(this.privateKey, this.publicKey);
  }

  @Override
  public boolean equals(Object obj) {

    if (obj == this) {
      return true;
    }
    if ((obj == null) || !(obj instanceof AbstractSecurityAsymmetricKeyPair)) {
      return false;
    }
    AbstractSecurityAsymmetricKeyPair<?, ?> other = (AbstractSecurityAsymmetricKeyPair<?, ?>) obj;
    if (!Objects.equals(this.privateKey, other.privateKey)) {
      return false;
    }
    if (!Objects.equals(this.publicKey, other.publicKey)) {
      return false;
    }
    return true;
  }

}
