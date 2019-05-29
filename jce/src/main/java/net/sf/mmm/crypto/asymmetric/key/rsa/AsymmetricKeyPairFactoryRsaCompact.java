package net.sf.mmm.crypto.asymmetric.key.rsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import net.sf.mmm.crypto.CryptoBinaryFormat;
import net.sf.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPairFactory;

/**
 * Implementation of {@link AbstractAsymmetricKeyPairFactory} for RSA in
 * {@link CryptoBinaryFormat#FORMAT_COMPACT compact format}.
 *
 * @since 1.0.0
 */
public class AsymmetricKeyPairFactoryRsaCompact
    extends AbstractAsymmetricKeyPairFactory<RSAPrivateKey, RSAPublicKey, AsymmetricKeyPairRsa> {

  private static final byte BYTE_OFFSET = 8;

  private static final int[] BYTE2POWER = new int[128];

  private static final byte[] HEADER_ENCODED_PUBLIC_KEY = new byte[] { 48, -126, 2, 34, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1,
  5, 0, 3, -126, 2, 15, 0, 48, -126, 2, 10, 2, -126, 2, 1, 0 };

  static {
    int power = 1 << BYTE_OFFSET;
    for (int i = 0; i < BYTE2POWER.length; i++) {
      BYTE2POWER[i] = power;
      power = power + power;
    }
  }

  /**
   * The constructor.
   */
  public AsymmetricKeyPairFactoryRsaCompact() {

    super(AsymmetricKeyPairRsa.getKeyFactory());
  }

  /**
   * The constructor.
   *
   * @param keyFactory the {@link KeyFactory}.
   */
  public AsymmetricKeyPairFactoryRsaCompact(KeyFactory keyFactory) {

    super(keyFactory);
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
  public byte[] asData(RSAPrivateKey privateKey) {

    BigInteger modulus = privateKey.getModulus();
    BigInteger privateExponent = privateKey.getPrivateExponent();
    byte[] modulusBytes = modulus.toByteArray();
    byte[] privateExponentBytes = privateExponent.toByteArray();
    int length = modulusBytes.length + privateExponentBytes.length;
    byte[] data = new byte[length];
    Byte modulusLength = length2byte(modulusBytes.length - 1);
    if (modulusLength == null) {
      throw new IllegalStateException("Not implemented for bit-length " + modulus.bitLength() + " that is not a power of 2!");
    }
    data[0] = modulusLength.byteValue();
    System.arraycopy(modulusBytes, 1, data, 1, modulusBytes.length - 1);
    System.arraycopy(privateExponentBytes, 0, data, modulusBytes.length, privateExponentBytes.length);
    return data;
  }

  @Override
  public RSAPrivateKey createPrivateKey(byte[] data) {

    int modulusLengthByte = data[0];
    if (modulusLengthByte >= BYTE2POWER.length) {
      throw new IllegalArgumentException("Invalid encoded modulus length: " + modulusLengthByte);
    }
    int modulusLength = BYTE2POWER[modulusLengthByte];
    if (modulusLength == 0) { // TODO
      return null;
    }
    byte[] modulusBytes = new byte[modulusLength];
    System.arraycopy(data, 1, modulusBytes, 0, modulusLength);
    BigInteger modulus = new BigInteger(1, modulusBytes);
    int privateExponentLength = data.length - modulusLength - 1;
    byte[] privateExponentBytes = new byte[privateExponentLength];
    System.arraycopy(data, modulusLength + 1, privateExponentBytes, 0, privateExponentLength);
    BigInteger privateExponent = new BigInteger(privateExponentBytes);
    return AsymmetricKeyPairRsa.createPrivateKey(modulus, privateExponent);
  }

  @Override
  public byte[] asData(RSAPublicKey publicKey) {

    BigInteger publicExponent = publicKey.getPublicExponent();
    boolean defaultPublicExponent = publicExponent.equals(AsymmetricKeyPairRsa.PUBLIC_EXPONENT);
    if (!defaultPublicExponent) {
      throw new IllegalStateException("Not implemented for non-default public exponent!");
    }
    byte[] data = publicKey.getModulus().toByteArray();
    return data;
  }

  @Override
  public RSAPublicKey createPublicKey(byte[] data) {

    //
    if (data.length > HEADER_ENCODED_PUBLIC_KEY.length) {
      boolean headerMatch = true;
      for (int i = 0; i < HEADER_ENCODED_PUBLIC_KEY.length; i++) {
        if (data[i] != HEADER_ENCODED_PUBLIC_KEY[i]) {
          headerMatch = false;
          break;
        }
      }
      if (headerMatch) {
        return null;
      }
    }
    BigInteger modulus = new BigInteger(data);
    return AsymmetricKeyPairRsa.createPublicKey(modulus);
  }

  @Override
  public byte[] asData(AsymmetricKeyPairRsa keyPair) {

    BigInteger publicExponent = keyPair.getPublicKey().getPublicExponent();
    boolean defaultPublicExponent = publicExponent.equals(AsymmetricKeyPairRsa.PUBLIC_EXPONENT);
    if (!defaultPublicExponent) {
      throw new IllegalStateException("Not implemented for non-default public exponent!");
    }
    return asData(keyPair.getPrivateKey());
  }

  @Override
  public AsymmetricKeyPairRsa createKeyPair(byte[] data) {

    RSAPrivateKey privateKey = createPrivateKey(data);
    RSAPublicKey publicKey = AsymmetricKeyPairRsa.createPublicKey(privateKey.getModulus());
    return new AsymmetricKeyPairRsa(privateKey, publicKey);
  }

  @Override
  public AsymmetricKeyPairRsa createKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey) {

    return new AsymmetricKeyPairRsa(privateKey, publicKey);
  }

}
