package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.SecurityKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeySpecFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKeySpecFactory;

import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Implementation of {@link SecurityPrivateKeySpecFactory} for {@link SecurityPrivateKeyEcBc}.
 *
 * @param <K> type of the {@link SecurityKey} corresponding to the {@link KeySpec}.
 * @since 1.0.0
 */
public abstract class SecurityAsymmetricKeySpecFactoryEcBc<K extends SecurityKey<?>> implements SecurityAsymmetricKeySpecFactory<K> {

  /** The {@link ECParameterSpec} of the elliptic curve. */
  protected final ECParameterSpec ecParameters;

  private final int keyLength;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec} defining the elliptic curve.
   */
  public SecurityAsymmetricKeySpecFactoryEcBc(ECParameterSpec ecParameters) {

    super();
    this.ecParameters = ecParameters;
    this.keyLength = calculateKeyLength();
  }

  /**
   * @return the (maximum) key length in bytes of the {@link net.sf.mmm.security.api.key.SecurityKey#getData() compact
   *         key data}.
   */
  protected int calculateKeyLength() {

    int byteLength = (this.ecParameters.getCurve().getOrder().bitLength() + 7) / 8;
    return byteLength + 1;
  }

  /**
   * @return the length of the compact key in bytes.
   */
  public int getKeyLength() {

    return this.keyLength;
  }

}
