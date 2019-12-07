package io.github.mmm.crypto.asymmetric.key;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Abstract base implementation of {@link AsymmetricKeyPair}.
 *
 * @param <PR> type of {@link #getPrivateKey() private key}.
 * @param <PU> type of {@link #getPublicKey() public key}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractAsymmetricKeyPair<PR extends PrivateKey, PU extends PublicKey>
    implements AsymmetricKeyPair<PR, PU> {

  /** @see #getPrivateKey() */
  protected final PR privateKey;

  /** @see #getPublicKey() */
  protected final PU publicKey;

  private final KeyPair keyPair;

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public AbstractAsymmetricKeyPair(PR privateKey, PU publicKey) {

    this(privateKey, publicKey, null);
  }

  /**
   * The constructor.
   *
   * @param keyPair the {@link #getKeyPair() key pair}.
   */
  @SuppressWarnings("unchecked")
  public AbstractAsymmetricKeyPair(KeyPair keyPair) {

    super();
    Objects.requireNonNull(keyPair, "keyPair");
    this.privateKey = (PR) keyPair.getPrivate();
    this.publicKey = (PU) keyPair.getPublic();
    Objects.requireNonNull(this.privateKey, "privateKey");
    Objects.requireNonNull(this.publicKey, "publicKey");
    this.keyPair = keyPair;
  }

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   * @param keyPair the {@link #getKeyPair() key pair}.
   */
  public AbstractAsymmetricKeyPair(PR privateKey, PU publicKey, KeyPair keyPair) {

    super();
    Objects.requireNonNull(privateKey, "privateKey");
    Objects.requireNonNull(publicKey, "publicKey");
    if (keyPair == null) {
      this.keyPair = new KeyPair(publicKey, privateKey);
    } else {
      if ((keyPair.getPrivate() != privateKey) || (keyPair.getPublic() != publicKey)) {
        throw new IllegalStateException("KeyPair does not match given keys.");
      }
      this.keyPair = keyPair;
    }
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  @Override
  public PR getPrivateKey() {

    return this.privateKey;
  }

  @Override
  public PU getPublicKey() {

    return this.publicKey;
  }

  @Override
  public KeyPair getKeyPair() {

    return this.keyPair;
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
    if ((obj == null) || !(obj instanceof AbstractAsymmetricKeyPair)) {
      return false;
    }
    AbstractAsymmetricKeyPair<?, ?> other = (AbstractAsymmetricKeyPair<?, ?>) obj;
    if (!Objects.equals(this.privateKey, other.privateKey)) {
      return false;
    }
    if (!Objects.equals(this.publicKey, other.publicKey)) {
      return false;
    }
    return true;
  }

}
