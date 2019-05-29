package net.sf.mmm.crypto.algorithm;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Abstract class for configuration of {@link AlgorithmParameterSpec}.
 *
 * @since 1.0.0
 */
public abstract class CryptoAlgorithmParameterConfig {

  /**
   * @return the {@link AlgorithmParameterSpec}.
   */
  public abstract AlgorithmParameterSpec getAlgorithmParameters();

}
