package net.sf.mmm.security.api.sign;

import net.sf.mmm.security.api.AbstractSecurityFactoryBuilder;
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
   * <b>ATTENTION:</b><br>
   * Please note that this method only works for
   * {@link net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfig#isBidirectional() bidirectional
   * encryption algorithms}.
   *
   * @param hashFactory the {@link SecurityHashFactory}.
   * @return the {@link SecuritySignatureFactory} with the given {@link SecurityHashFactory} used in advance to create a
   *         {@link net.sf.mmm.security.api.hash.SecurityHashCreator#hash() hash} that is then signed using the
   *         configured cryptographic algorithm.
   */
  SecuritySignatureFactory signUsingCryptor(SecurityHashFactory hashFactory);

  /**
   * <b>ATTENTION:</b><br>
   * Please note that this method only works for
   * {@link net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfig#isBidirectional() bidirectional
   * encryption algorithms}.
   *
   * @return the {@link SecuritySignatureFactory} combining the {@link net.sf.mmm.security.api.hash.SecurityHashFactory}
   *         in advance to create a {@link net.sf.mmm.security.api.hash.SecurityHashCreator#hash() hash} that is then
   *         signed by "encrypting" the hash with the
   *         {@link net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactory}.
   */
  SecuritySignatureFactory signUsingHashAndCryptor();

}
