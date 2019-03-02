/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmCurve25519;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSecp256k1;
import net.sf.mmm.security.api.provider.BouncyCastleInstaller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Direct builder for {@link SecurityAlgorithmCurve25519 Curve 25519}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class Secp256k1 extends AbstractSecurityAsymmetricCryptorBuilderEcDsa<Secp256k1> {

  static final SecurityAlgorithmParameterConfigEcBc CURVE = new SecurityAlgorithmParameterConfigEcBc(
      SecurityAlgorithmSecp256k1.ALGORITHM_SECP_256K1);

  private final SecurityAsymmetricCryptorConfigSecp256k1 config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfigEcies}.
   */
  public Secp256k1(SecurityAsymmetricCryptorConfigSecp256k1 config) {

    super();
    BouncyCastleInstaller.install();
    this.config = config;
    getFactoryBuilder().provider(BouncyCastleProvider.PROVIDER_NAME);
  }

  @Override
  protected SecurityAsymmetricCryptorConfigSecp256k1 getCryptorConfig() {

    return this.config;
  }

  /**
   * @return a new {@link Secp256k1} instance.
   */
  public static Secp256k1 create() {

    return new Secp256k1(SecurityAsymmetricCryptorConfigSecp256k1.SECP_256K1);
  }

}
