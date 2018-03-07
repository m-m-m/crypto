package net.sf.mmm.security.api.crypt.asymmetric;

/**
 * Extends {@link SecurityAsymmetricCryptorFactory} for bidirectional cryptography where you can encrypt using
 * {@link java.security.PublicKey} and decrypt using {@link java.security.PrivateKey} as well as encrypt using
 * {@link java.security.PrivateKey} and decrypt using {@link java.security.PublicKey} such as e.g.
 * {@link SecurityAsymmetricCryptorConfigRsa RSA}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricCryptorFactoryBidirectional
    extends SecurityAsymmetricCryptorFactoryPrivatePublic, SecurityAsymmetricCryptorFactoryPublicPrivate {

}
