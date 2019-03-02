package net.sf.mmm.security.api.key.asymmetric.ec.jce;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.ec.bc.SecurityPrivateKeyEcBc;
import net.sf.mmm.security.api.key.asymmetric.ec.bc.SecurityPublicKeyEcBc;
import net.sf.mmm.util.datatype.api.Binary;

/**
 * An implementation of {@link SecurityAsymmetricKeyPair} for {@link SecurityPrivateKeyEcBc} and
 * {@link SecurityPublicKeyEcBc}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairEcJce extends AbstractSecurityAsymmetricKeyPair<SecurityPrivateKeyEcJce, SecurityPublicKeyEcJce> {

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairEcJce(SecurityPrivateKeyEcJce privateKey, SecurityPublicKeyEcJce publicKey) {

    super(privateKey, publicKey);
  }

  @Override
  public Binary asBinary() {

    return getPrivateKey();
  }

}
