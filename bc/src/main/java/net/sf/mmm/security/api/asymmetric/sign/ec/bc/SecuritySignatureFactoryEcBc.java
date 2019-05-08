package net.sf.mmm.security.api.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.security.api.asymmetric.access.ec.bc.SecurityEllipticCurveBc;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

/**
 * Implementation of {@link SecuritySignatureFactory} for {@link SecuritySignatureEcBc}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @since 1.0.0
 */
public abstract class SecuritySignatureFactoryEcBc<S extends SecuritySignatureEcBc> implements SecuritySignatureFactory<S> {

  /** The {@link SecurityEllipticCurveBc elliptic curve}. */
  protected final SecurityEllipticCurveBc curve;

  /**
   * The constructor.
   *
   * @param curve the {@link SecurityEllipticCurveBc elliptic curve}.
   */
  public SecuritySignatureFactoryEcBc(SecurityEllipticCurveBc curve) {

    super();
    this.curve = curve;
  }

  /**
   * @param r the value {@link SecuritySignatureEcBc#getR() r}.
   * @param s the value {@link SecuritySignatureEcBc#getS() s}.
   * @param message the signed message (hash).
   * @param publicKey the {@link BCECPublicKey} that was used to sign the message.
   * @return the signature.
   */
  public abstract S create(BigInteger r, BigInteger s, byte[] message, BCECPublicKey publicKey);

}
