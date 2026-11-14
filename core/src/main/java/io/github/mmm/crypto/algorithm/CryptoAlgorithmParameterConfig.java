package io.github.mmm.crypto.algorithm;

import java.security.spec.AlgorithmParameterSpec;

/// Abstract class for configuration of [AlgorithmParameterSpec].
///
/// @since 1.0.0
public abstract class CryptoAlgorithmParameterConfig {

  /// @return the [AlgorithmParameterSpec].
  public abstract AlgorithmParameterSpec getAlgorithmParameters();

}
