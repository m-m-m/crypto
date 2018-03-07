package net.sf.mmm.security.api.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.AbstractSecurityFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

/**
 * Interface for a {@link AbstractSecurityFactory factory} to create instances of {@link SecuritySignatureCreator} for
 * {@link net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair asymmetric cryptography}. As
 * signatures are intended for {@link SecuritySignatureVerifier#verifyAfterUpdate(byte[]) verification} of the public this makes
 * only sense with asymmetric security. Instead with symmetric encryption the secret key would have to be known to the
 * public allowing anybody to create faked signatures that would also be valid.<br>
 * Use {@link #newSigner(SecurityPrivateKey)} for signing and {@link #newVerifier(SecurityPublicKey)} for verification.
 * <br>
 * An instance of {@link SecuritySignatureFactory} typically combines asymmetric
 * {@link net.sf.mmm.security.api.crypt.SecurityCryptor cryptography} with
 * {@link net.sf.mmm.security.api.hash.SecurityHashCreator hashing}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureFactory extends AbstractSecurityFactory {

  /** {@link #getType() Type} of this factory. */
  String TYPE = "SignatureFactory";

  /**
   * @param privateKey the {@link SecurityPrivateKey} to use for signing.
   * @return the {@link SecuritySignatureSigner} for signing.
   */
  default SecuritySignatureSigner newSigner(SecurityPrivateKey privateKey) {

    return newSigner(privateKey.getKey());
  }

  /**
   * @param privateKey the {@link PrivateKey} to use for signing.
   * @return the {@link SecuritySignatureSigner} for signing.
   */
  SecuritySignatureSigner newSigner(PrivateKey privateKey);

  /**
   * @param publicKey the {@link SecurityPublicKey} to use for verifying.
   * @return the {@link SecuritySignatureVerifier} for verifying.
   */
  default SecuritySignatureVerifier newVerifier(SecurityPublicKey publicKey) {

    return newVerifier(publicKey.getKey());
  }

  /**
   * @param publicKey the {@link PublicKey} to use for verifying.
   * @return the {@link SecuritySignatureVerifier} for verifying.
   */
  SecuritySignatureVerifier newVerifier(PublicKey publicKey);

  @Override
  default String getType() {

    return TYPE;
  }

}
