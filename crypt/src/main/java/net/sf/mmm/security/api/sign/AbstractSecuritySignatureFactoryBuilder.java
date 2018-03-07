package net.sf.mmm.security.api.sign;

import net.sf.mmm.security.api.AbstractSecurityFactoryBuilder;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.hash.SecurityHashFactory;

/**
 * Abstract interface for {@link SecuritySignatureFactoryBuilder}.
 *
 * @see net.sf.mmm.security.api.SecurityBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySignatureFactoryBuilder extends AbstractSecurityFactoryBuilder {

  /**
   * @param hashFactory the {@link SecurityHashFactory} that is used in advance to build a hash that is then signed
   *        using the configured cryptor.
   * @return the {@link SecuritySignatureFactory} for the configured cryptor and the given {@link SecurityHashFactory}.
   */
  SecuritySignatureFactory signUsingCryptor(SecurityHashFactory hashFactory);

  /**
   * @param hashFactory the {@link SecurityHashFactory} that is used in advance to build a hash that is then signed
   *        using the given {@link SecurityCryptorFactory} to encrypt the hash.
   * @param cryptorFactory the {@link SecurityCryptorFactory} used to encrypt the hash for signing and decrypt it for
   *        verification.
   * @return the {@link SecuritySignatureFactory} for the configured cryptor and hash.
   */
  SecuritySignatureFactory signUsingHashAndCryptor();

}
