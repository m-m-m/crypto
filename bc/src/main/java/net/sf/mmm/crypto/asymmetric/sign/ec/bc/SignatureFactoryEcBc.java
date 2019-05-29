package net.sf.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;
import net.sf.mmm.crypto.asymmetric.sign.SignatureBinary;
import net.sf.mmm.crypto.asymmetric.sign.SignatureFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

/**
 * Implementation of {@link SignatureFactory} for {@link SignatureEcBc}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @since 1.0.0
 */
public abstract class SignatureFactoryEcBc<S extends SignatureEcBc> implements SignatureFactory<S> {

  /** The {@link CryptoEllipticCurveBc elliptic curve}. */
  protected final CryptoEllipticCurveBc curve;

  /**
   * The constructor.
   *
   * @param curve the {@link CryptoEllipticCurveBc elliptic curve}.
   */
  public SignatureFactoryEcBc(CryptoEllipticCurveBc curve) {

    super();
    this.curve = curve;
  }

  /**
   * @param r the value {@link SignatureEcBc#getR() r}.
   * @param s the value {@link SignatureEcBc#getS() s}.
   * @param message the signed message (hash).
   * @param publicKey the {@link BCECPublicKey} that was used to sign the message.
   * @return the signature.
   */
  public abstract S create(BigInteger r, BigInteger s, byte[] message, BCECPublicKey publicKey);

}
