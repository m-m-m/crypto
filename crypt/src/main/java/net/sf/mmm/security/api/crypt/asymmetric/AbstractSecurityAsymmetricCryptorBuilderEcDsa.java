package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcDsa;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.sign.SecuritySignatureConfig;

/**
 * Extends {@link AbstractSecurityAsymmetricCryptorBuilder} for {@link SecurityAlgorithmEcDsa ECDSA}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 * @param <B> type of the returned builder.
 */
public abstract class AbstractSecurityAsymmetricCryptorBuilderEcDsa<B extends AbstractSecurityAsymmetricCryptorBuilderEcDsa<B>>
    extends AbstractSecurityAsymmetricCryptorBuilder<B> {

  @Override
  protected SecuritySignatureConfig getSignatureConfig() {

    SecurityHashConfig hashConfig = getHashConfig();
    if (hashConfig == null) {
      throw new IllegalStateException(
          "Hashing is required for signature but not configured. Please call hash(...) or withHash(...) before using signature.");
    }
    return new SecuritySignatureConfig(hashConfig, SecurityAlgorithmEcDsa.ALGORITHM_ECDSA);
  }

}
