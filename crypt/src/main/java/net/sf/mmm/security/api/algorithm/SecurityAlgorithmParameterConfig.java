package net.sf.mmm.security.api.algorithm;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Abstract class for configuration of {@link AlgorithmParameterSpec}.
 *
 * @since 1.0.0
 */
public abstract class SecurityAlgorithmParameterConfig {

  /**
   * @return the {@link AlgorithmParameterSpec}.
   */
  public abstract AlgorithmParameterSpec getAlgorithmParameters();

}
