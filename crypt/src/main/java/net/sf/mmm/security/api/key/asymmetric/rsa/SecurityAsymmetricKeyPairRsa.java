package net.sf.mmm.security.api.key.asymmetric.rsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.util.datatype.api.Binary;
import net.sf.mmm.util.datatype.api.BinaryType;

/**
 * An implementation of {@link SecurityAsymmetricKeyPair} for {@link net.sf.mmm.security.api.crypt.asymmetric.Rsa}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairRsa extends AbstractSecurityAsymmetricKeyPair<SecurityPrivateKeyRsa, SecurityPublicKeyRsa> {

  /** The (default) public exponent for RSA key generation. */
  private static BigInteger PUBLIC_EXPONENT = new BigInteger("65537");

  private static final byte BYTE_OFFSET = 8;

  private static final int[] BYTE2POWER = new int[128];

  static {
    int power = 1 << BYTE_OFFSET;
    for (int i = 0; i < BYTE2POWER.length; i++) {
      BYTE2POWER[i] = power;
      power = power + power;
    }
  }

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairRsa(SecurityPrivateKeyRsa privateKey, SecurityPublicKeyRsa publicKey) {

    super(privateKey, publicKey);
  }

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairRsa(RSAPrivateKey privateKey, RSAPublicKey publicKey) {

    super(new SecurityPrivateKeyRsa(privateKey), new SecurityPublicKeyRsa(publicKey));
  }

  /**
   * @return the {@link RSAPrivateKey}.
   */
  public RSAPrivateKey getRsaPrivateKey() {

    return this.privateKey.getKey();
  }

  /**
   * @return the {@link RSAPublicKey}.
   */
  public RSAPublicKey getRsaPublicKey() {

    return this.publicKey.getKey();
  }

  private Byte length2byte(int length) {

    for (byte i = 0; i < BYTE2POWER.length; i++) {
      int power = BYTE2POWER[i];
      if (power == length) {
        return Byte.valueOf(i);
      } else if (power > length) {
        break;
      }
    }
    return null;
  }

  @Override
  public Binary asBinary() {

    RSAPrivateKey rsaPrivateKey = getRsaPrivateKey();
    BigInteger modulus = rsaPrivateKey.getModulus();
    BigInteger privateExponent = rsaPrivateKey.getPrivateExponent();
    byte[] modulusBytes = modulus.toByteArray();
    Byte modulusLength = length2byte(modulusBytes.length);
    byte[] privateExponentBytes = privateExponent.toByteArray();
    int length = modulusBytes.length + privateExponentBytes.length + 1;
    BigInteger publicExponent = getRsaPublicKey().getPublicExponent();
    boolean defaultPublicExponent = publicExponent.equals(PUBLIC_EXPONENT);
    if (defaultPublicExponent) {

    } else {
      byte[] publicExponentBytes = privateExponent.toByteArray();
      length = length + 1 + publicExponentBytes.length;

    }
    byte[] bytes = new byte[length];
    // this.privateKey.getData(bytes, 0);
    // this.publicKey.getData(bytes, this.privateKey.getLength());
    return new BinaryType(bytes);
  }

  /**
   * @param modulus is the {@link RSAKey#getModulus() modulus} (product of two large primes).
   * @param privateExponent the {@link RSAPrivateKey#getPrivateExponent() private exponent}.
   * @param publicExponent the {@link RSAPublicKey#getPublicExponent() public exponent}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public static SecurityAsymmetricKeyPairRsa of(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent) {

    try {
      KeyFactory factory = KeyFactory.getInstance(SecurityAlgorithmRsa.ALGORITHM_RSA);
      RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
      RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      return new SecurityAsymmetricKeyPairRsa(privateKey, publicKey);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * @param modulus is the {@link RSAKey#getModulus() modulus} (product of two large primes).
   * @param privateExponent the {@link RSAPrivateKey#getPrivateExponent() private exponent}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public static SecurityAsymmetricKeyPair of(BigInteger modulus, BigInteger privateExponent) {

    return of(modulus, privateExponent, PUBLIC_EXPONENT);
  }

  /**
   * @param modulus is the modulus (product of two large primes).
   * @param privateExponent the private key encryption exponent.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public static SecurityAsymmetricKeyPair createKeyPair(String modulus, String privateExponent) {

    return of(new BigInteger(modulus), new BigInteger(privateExponent), PUBLIC_EXPONENT);
  }

}
