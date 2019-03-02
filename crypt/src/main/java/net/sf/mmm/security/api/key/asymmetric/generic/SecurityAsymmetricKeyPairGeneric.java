package net.sf.mmm.security.api.key.asymmetric.generic;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.util.datatype.api.Binary;
import net.sf.mmm.util.datatype.api.BinaryType;

/**
 * A generic implementation of {@link SecurityAsymmetricKeyPair}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairGeneric extends AbstractSecurityAsymmetricKeyPair<SecurityPrivateKey, SecurityPublicKey> {

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairGeneric(PrivateKey privateKey, PublicKey publicKey) {

    super(new SecurityPrivateKeyGeneric(privateKey), new SecurityPublicKeyGeneric(publicKey));
  }

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairGeneric(SecurityPrivateKey privateKey, SecurityPublicKey publicKey) {

    super(privateKey, publicKey);
  }

  @Override
  public Binary asBinary() {

    int length = this.privateKey.getLength() + this.publicKey.getLength();
    byte[] bytes = new byte[length];
    this.privateKey.getData(bytes, 0);
    this.publicKey.getData(bytes, this.privateKey.getLength());
    return new BinaryType(bytes);
  }

}
