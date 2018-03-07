package net.sf.mmm.security.api.key.asymmetric;

import java.util.Objects;

/**
 * A generic implementation of {@link SecurityAsymmetricKeyPair}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairGeneric implements SecurityAsymmetricKeyPair {

  private final SecurityPrivateKey privateKey;

  private final SecurityPublicKey publicKey;

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairGeneric(SecurityPrivateKey privateKey, SecurityPublicKey publicKey) {

    super();
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  @Override
  public SecurityPrivateKey getPrivateKey() {

    return this.privateKey;
  }

  @Override
  public SecurityPublicKey getPublicKey() {

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
    if ((obj == null) || !(obj instanceof SecurityAsymmetricKeyPairGeneric)) {
      return false;
    }
    SecurityAsymmetricKeyPairGeneric other = (SecurityAsymmetricKeyPairGeneric) obj;
    if (!Objects.equals(this.privateKey, other.privateKey)) {
      return false;
    }
    if (!Objects.equals(this.publicKey, other.publicKey)) {
      return false;
    }
    return true;
  }

}
