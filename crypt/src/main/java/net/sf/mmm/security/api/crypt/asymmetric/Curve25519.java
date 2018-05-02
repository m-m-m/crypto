/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmCurve25519;
import net.sf.mmm.security.api.sign.SecuritySignatureConfig;

/**
 * Direct builder for {@link SecurityAlgorithmCurve25519 Curve 25519}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class Curve25519 extends AbstractSecurityAsymmetricCryptorBuilderPublicPrivate<Curve25519> {

  private final SecurityAsymmetricCryptorConfigCurve25519 config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfigEcies}.
   */
  public Curve25519(SecurityAsymmetricCryptorConfigCurve25519 config) {

    super();
    this.config = config;
  }

  @Override
  protected SecurityAsymmetricCryptorConfigCurve25519 getCryptorConfig() {

    return this.config;
  }

  /**
   * @return a new {@link Curve25519} instance.
   */
  public static Curve25519 create() {

    return new Curve25519(SecurityAsymmetricCryptorConfigCurve25519.CURVE_25519);
  }

  @Override
  protected SecuritySignatureConfig getSignatureConfig() {

    return new SecuritySignatureConfig(SecuritySignatureConfig.SIGNATURE_ALGORITHM_ECDSA);
  }

}
