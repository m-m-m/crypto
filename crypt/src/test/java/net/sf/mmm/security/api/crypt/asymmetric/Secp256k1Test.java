/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.hash.SecurityHashConfigSha256;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.util.datatype.api.BinaryType;

import org.junit.Test;

/**
 * Test of {@link Secp256k1}.
 */
public class Secp256k1Test extends SecurityAsymmetricCryptorBuilderTest {

  /**
   * Test of {@link Secp256k1#create()}.
   */
  @Test
  public void testSecp256k1() {

    // given
    Secp256k1 secp256k1 = Secp256k1.create();
    assertThat(secp256k1.getAlgorithm()).isEqualTo("ECIES");
    assertThat(secp256k1.getCryptorConfig().getKeyAlgorithmConfig().getKeyLength()).isEqualTo(256);

    // when + then
    verify(secp256k1, 99);
  }

  @Override
  protected int getSignatureMinLength() {

    return 69;
  }

  @Override
  protected int getSignatureLength() {

    return 72;
  }

  @Override
  protected int getPrivateKeyCompactMinLength() {

    return 32;
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

  @Override
  protected void verifyKeyPair(SecurityAsymmetricKeyPair keyPair, SecurityAsymmetricKeyCreator keyCreator) {

    super.verifyKeyPair(keyPair, keyCreator);
    assertThat(keyPair.getPrivateKey().getLength()).as("privateKey.length").isLessThanOrEqualTo(33);
    // TODO make 32 byte representation normal form
    // assertThat(keyPair.getPublicKey().getLength()).as("publicKey.length").isEqualTo(32);
    assertThat(keyPair.getPublicKey().getLength()).as("publicKey.length").isEqualTo(33);
  }

  @Test
  public void testSecp256k1KeyPairFromBitcoin() {

    Secp256k1 secp256k1 = Secp256k1.create();
    SecurityAsymmetricKeyCreator keyCreator = secp256k1.newKeyCreator();
    // https://en.bitcoin.it/wiki/Private_key
    // https://privatekeys.pw/key/5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF

    // private key
    String privateKeyHex = "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262";
    byte[] privateKeyBytes = BinaryType.parseHex(privateKeyHex);
    SecurityPrivateKey privateKey = keyCreator.deserializePrivateKey(privateKeyBytes);
    assertThat(privateKey.getHex()).isEqualTo(privateKeyHex);

    // public key
    String publicKeyHex = "02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9";
    byte[] publicKeyBytes = BinaryType.parseHex(publicKeyHex);
    SecurityPublicKey publicKey = keyCreator.deserializePublicKey(publicKeyBytes);
    assertThat(publicKey.getHex()).isEqualTo(publicKeyHex);

    // key pair (generate public key from private key)
    // ECKey key = new ECKey(privKey, true);
    // byte[] pubKey = key.getPubKey();
    SecurityAsymmetricKeyPair keyPair = keyCreator.deserializeKeyPair(privateKeyBytes);
    publicKey = keyPair.getPublicKey();
    assertThat(publicKey.getHex()).isEqualTo(publicKeyHex);
  }

  @Test
  public void testSecp256k1Sign() throws Exception {

    String privateKeyHex = "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262";
    byte[] privateKeyBytes = BinaryType.parseHex(privateKeyHex);
    Secp256k1 secp256k1 = Secp256k1.create();
    SecurityAsymmetricKeyCreator keyCreator = secp256k1.newKeyCreator();
    SecurityAsymmetricKeyPair keyPair = keyCreator.deserializeKeyPair(privateKeyBytes);
    SecurityPrivateKey privateKey = keyPair.getPrivateKey();
    SecurityPublicKey publicKey = keyPair.getPublicKey();
    secp256k1.hash(new SecurityHashConfigSha256(2));
    SecuritySignatureFactory signatureFactory = secp256k1.sign();
    byte[] data = "Secret message".getBytes("UTF-8");
    byte[] signature = signatureFactory.newSigner(privateKey).sign(data, true);
    String sgn = BinaryType.formatBase64(signature);
    String expectedSignature = "MEUCIEi1DCSNB97hr+YEWf+ZbP7P6dWyEH5iRuudz6rraCkFAiEAqBUXzia4xtW7G7K1pHXWlm/gm7/46mgQGuRxi7Nd4Qo===";
    expectedSignature = "MEUCIHjHPqm7sRWW/iuZhoHv+sO5R9cc87a9ng+KyM+EW3vQAiEAgqF/U/zmxqh73eD5Cxazn3VCivEn+OPxBd1DNqxg154=";
    // assertThat(sgn).isEqualTo(expectedSignature);
    boolean valid = signatureFactory.newVerifier(publicKey).verify(data, signature);
    assertThat(valid).isTrue();
  }

}
