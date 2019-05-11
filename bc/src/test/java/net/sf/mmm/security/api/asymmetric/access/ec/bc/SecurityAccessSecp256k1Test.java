/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.asymmetric.access.ec.bc;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.binary.api.BinaryType;
import net.sf.mmm.security.api.SecurityBinaryFormat;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;
import net.sf.mmm.security.api.asymmetric.access.SecurityAccessAsymmetricTest;
import net.sf.mmm.security.api.asymmetric.access.rsa.SecurityAccessRsa;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.ec.bc.SecurityAsymmetricKeyCreatorEcBc;
import net.sf.mmm.security.api.asymmetric.key.ec.bc.SecurityAsymmetricKeyPairEcBc;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureEcBcPlain;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureEcBcWithRecoveryId;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.hash.SecurityHashConfig;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.Test;

/**
 * Test of {@link SecurityAccessSecp256k1}.
 */
@SuppressWarnings({ "rawtypes" })
public class SecurityAccessSecp256k1Test extends SecurityAccessAsymmetricTest {

  public static void main(String[] args) {

    String hashAlgorithm = SecurityAlgorithmSha2.ALGORITHM_SHA_256; // "SHA-256";
    SecurityHashConfig sha256x2 = new SecurityHashConfig(hashAlgorithm, 2);
    SecurityAccessRsa access = SecurityAccessRsa.of4096(sha256x2);
    SecurityAsymmetricKeyCreator keyCreator = access.newKeyCreator();
    SecurityAsymmetricKeyPair keyPair = keyCreator.generateKeyPair();
    PublicKey publicKey = keyPair.getPublicKey();
    PrivateKey privateKey = keyPair.getPrivateKey();
    // encryption + decryption
    byte[] rawMessage = "Secret message".getBytes(StandardCharsets.UTF_8);
    SecurityEncryptor encryptor = access.newEncryptorUnsafe(publicKey);
    byte[] encryptedMessage = encryptor.crypt(rawMessage, true);
    SecurityDecryptor decryptor = access.newDecryptorUnsafe(privateKey);
    byte[] decryptedMessage = decryptor.crypt(encryptedMessage, true);
    assertThat(decryptedMessage).isEqualTo(rawMessage);
    // signing
    SecuritySignature signature = access.newSignerUnsafe(privateKey).sign(rawMessage, true);
    boolean signatureVerified = access.newVerifierUnsafe(publicKey).verifyUnsafe(rawMessage, signature);
    assertThat(signatureVerified).as("signature verified").isTrue();
  }

  /**
   * Basic/generic test of {@link SecurityAccessSecp256k1#ofPlain(String)}.
   */
  @Test
  public void testSecp256k1() {

    // given
    SecurityAccessSecp256k1 secp256k1 = SecurityAccessSecp256k1.ofPlain(SecurityAlgorithmSha2.ALGORITHM_SHA_256);
    assertThat(secp256k1.getAlgorithm()).isEqualTo("ECIES");
    assertThat(secp256k1.newKeyCreator().getKeyLength()).isEqualTo(256);

    // when + then
    verify(secp256k1, 99);
  }

  @Override
  protected int getPrivateKeyCompactMinLength() {

    return 31;
  }

  @Override
  protected int getPrivateKeyCompactLength() {

    return 33;
  }

  @Override
  protected int getPrivateKeyEncodedLength() {

    return 591;
  }

  @Override
  protected int getPublicKeyCompactLength() {

    return 33;
  }

  @Override
  protected int getPublicKeyEncodedLength() {

    return 311;
  }

  /**
   * Test of {@link SecurityAccessSecp256k1#ofRecoveryId(SecurityHashConfig)} with official examples from BitCoin.
   */
  @Test
  public void testSecp256k1KeyPairFromBitcoin() {

    SecurityAccessSecp256k1<SecuritySignatureEcBcWithRecoveryId> secp256k1 = SecurityAccessSecp256k1
        .ofRecoveryId(new SecurityHashConfig(SecurityAlgorithmSha2.ALGORITHM_SHA_256, 1));
    SecurityAsymmetricKeyCreatorEcBc keyCreator = secp256k1.newKeyCreator();
    // https://en.bitcoin.it/wiki/Private_key
    // https://privatekeys.pw/key/5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF

    // private key
    String privateKeyHex = "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262";
    byte[] privateKeyBytes = BinaryType.parseHex(privateKeyHex);
    BCECPrivateKey privateKey = keyCreator.createPrivateKey(privateKeyBytes);
    assertThat(BinaryType.formatHex(keyCreator.asData(privateKey, SecurityBinaryFormat.FORMAT_COMPACT))).isEqualTo(privateKeyHex);

    // public key
    String publicKeyHex = "02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9";
    byte[] publicKeyBytes = BinaryType.parseHex(publicKeyHex);
    BCECPublicKey publicKey = keyCreator.createPublicKey(publicKeyBytes);
    assertThat(BinaryType.formatHex(keyCreator.asData(publicKey, SecurityBinaryFormat.FORMAT_COMPACT))).isEqualTo(publicKeyHex);

    // key pair (generate public key from private key)
    // ECKey key = new ECKey(privKey, true);
    // byte[] pubKey = key.getPubKey();
    SecurityAsymmetricKeyPairEcBc keyPair = keyCreator.createKeyPair(privateKeyBytes);
    publicKey = keyPair.getPublicKey();
    assertThat(BinaryType.formatHex(keyCreator.asData(publicKey, SecurityBinaryFormat.FORMAT_COMPACT))).isEqualTo(publicKeyHex);

    byte[] data = "Hello World!".getBytes();
    byte[] hash = secp256k1.newHashCreator().hash(data, true);
    SecuritySignatureEcBcWithRecoveryId signature = secp256k1.getSignatureFactoryWithoutHash().newSigner(privateKey).sign(hash, false);
    String signatureHex = signature.formatHex();
    assertThat(signatureHex).isEqualTo(
        "1fd1601269aac7205e00dee3a99cd3d666505e0466c7791f4b097ac237360f67ef344e0875c6a1328fc37e0964d52c6d199e9e6b2eb3a3ab94fb3f9e73d1fdba88");
    boolean valid = secp256k1.getSignatureFactoryWithoutHash().newVerifier(publicKey).verify(hash, signature);
    assertThat(valid).isTrue();
    BCECPublicKey recoveredPublicKey = signature.recoverPublicKey(hash);
    assertThat(recoveredPublicKey).isEqualTo(publicKey);
  }

  /**
   * Advanced signature test of {@link SecurityAccessSecp256k1#ofPlain(SecurityHashConfig)}.
   */
  @Test
  public void testSecp256k1Sign() {

    String privateKeyHex = "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262";
    byte[] privateKeyBytes = BinaryType.parseHex(privateKeyHex);
    SecurityAccessSecp256k1<SecuritySignatureEcBcPlain> secp256k1 = SecurityAccessSecp256k1
        .ofPlain(new SecurityHashConfig(SecurityAlgorithmSha2.ALGORITHM_SHA_256));
    SecurityAsymmetricKeyCreatorEcBc keyCreator = secp256k1.newKeyCreator();
    SecurityAsymmetricKeyPairEcBc keyPair = keyCreator.createKeyPair(privateKeyBytes);
    BCECPrivateKey privateKey = keyPair.getPrivateKey();
    BCECPublicKey publicKey = keyPair.getPublicKey();
    byte[] data = "Secret message".getBytes(StandardCharsets.UTF_8);

    SecuritySignatureEcBcPlain signature = secp256k1.newSigner(privateKey).sign(data, true);
    String sgn = signature.formatBase64();
    String expectedSignature = "DuIxpsDRrY5pSWHuKkxbDaRfgswM7MqgqyUJ1zLu3zFi44a4JU0Ons/79jRO1jsmemzKEsehY+QQxqdZ1+SStg==";
    assertThat(sgn).isEqualTo(expectedSignature);
    boolean valid = secp256k1.newVerifier(publicKey).verify(data, signature);
    assertThat(valid).isTrue();

    signature = secp256k1.getSignatureFactoryWithoutHash().newSigner(privateKey).sign(data, true);
    sgn = signature.formatBase64();
    expectedSignature = "b0yW5nSE/uTjG9CqT360w2IfWqvlg3S8zE6fDsnxCDwzGkk5oXB8wpfw9pL7AlZTrw3s+Ld6le6Mx8cb2MCqEg==";
    assertThat(sgn).isEqualTo(expectedSignature);
    valid = secp256k1.getSignatureFactoryWithoutHash().newVerifier(publicKey).verify(data, signature);
    assertThat(valid).isTrue();
  }

}
