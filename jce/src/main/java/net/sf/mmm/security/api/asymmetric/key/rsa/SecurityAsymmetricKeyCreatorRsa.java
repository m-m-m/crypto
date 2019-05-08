package net.sf.mmm.security.api.asymmetric.key.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.provider.SecurityProvider;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Implementation of {@link SecurityAsymmetricKeyCreator} for {@link SecurityAlgorithmRsa RSA}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyCreatorRsa extends
    AbstractSecurityAsymmetricKeyCreator<RSAPrivateKey, RSAPublicKey, SecurityAsymmetricKeyPairRsa> implements SecurityAlgorithmRsa {

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length}.
   */
  public SecurityAsymmetricKeyCreatorRsa(int keyLength) {

    this(keyLength, null, null);
  }

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param provider the {@link #getProvider() provider}.
   * @param randomFactory the {@link #getRandomFactory() random factory}.
   */
  public SecurityAsymmetricKeyCreatorRsa(int keyLength, SecurityProvider provider, SecurityRandomFactory randomFactory) {

    super(SecurityAsymmetricKeyPairRsa.getKeyFactory(), keyLength, provider, randomFactory);
    register(new SecurityAsymmetricKeyPairFactoryRsaCompact());
  }

  @Override
  public SecurityAsymmetricKeyPairRsa createKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey) {

    return new SecurityAsymmetricKeyPairRsa(privateKey, publicKey);
  }

  @Override
  public int getKeyLength(RSAPrivateKey privateKey) {

    Objects.requireNonNull(privateKey, "privateKey");
    return privateKey.getModulus().bitLength();
  }

  @Override
  public int getKeyLength(RSAPublicKey publicKey) {

    Objects.requireNonNull(publicKey, "publicKey");
    return publicKey.getModulus().bitLength();
  }

}
