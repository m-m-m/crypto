package net.sf.mmm.security.api.sign;

import net.sf.mmm.security.api.SecurityChunker;
import net.sf.mmm.security.api.hash.SecurityHashCreator;

/**
 * The abstract interface for an signing or verification function of an asymmetric
 * {@link net.sf.mmm.security.api.crypt.SecurityCryptor cryptographic algorithm} typically in combination
 * with a {@link SecurityHashCreator hasing algorithm}. It is similar to {@link java.security.Signature} but gives additional
 * abstraction and flexibility.
 *
 * @see SecuritySignatureSigner
 * @see SecuritySignatureVerifier
 * @see SecuritySignatureFactory
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecuritySignatureCreator extends SecurityChunker {

}
