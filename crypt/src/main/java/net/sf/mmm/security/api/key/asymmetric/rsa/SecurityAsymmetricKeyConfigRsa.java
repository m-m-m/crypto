package net.sf.mmm.security.api.key.asymmetric.rsa;

import java.security.KeyFactory;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

/**
 * {@link SecurityAsymmetricKeyConfig} for {@link net.sf.mmm.security.api.crypt.asymmetric.Rsa}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfigRsa extends SecurityAsymmetricKeyConfig implements SecurityAlgorithmRsa {

  /** {@link #ALGORITHM_RSA RSA} with a {@link #getKeyLength() key length} of 4096 bits. */
  public static final SecurityAsymmetricKeyConfigRsa RSA_4096 = new SecurityAsymmetricKeyConfigRsa(4096);

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecurityAsymmetricKeyConfigRsa(int keyLength) {

    super(ALGORITHM_RSA, keyLength);
  }

  @Override
  public SecurityAsymmetricKeyPairFactoryRsa getKeyPairFactory() {

    return SecurityAsymmetricKeyPairFactoryRsa.get();
  }

  @Override
  public SecurityPrivateKey deserializePrivateKey(byte[] privateKeyData, KeyFactory keyFactory) throws Exception {

    // TODO Auto-generated method stub
    return super.deserializePrivateKey(privateKeyData, keyFactory);
  }

  @Override
  public SecurityPublicKey deserializePublicKey(byte[] publicKeyData, KeyFactory keyFactory) throws Exception {

    // TODO Auto-generated method stub
    return super.deserializePublicKey(publicKeyData, keyFactory);
  }

  @Override
  public SecurityAsymmetricKeyPair deserializeKeyPair(byte[] keyPairBytes, KeyFactory keyFactory) throws Exception {

    // TODO Auto-generated method stub
    return null;
  }

}
