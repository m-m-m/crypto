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
   * @param hashFactory the {@link SecurityHashFactory}.
   * @return the {@link SecuritySignatureFactory} with the given {@link SecurityHashFactory} used in advance to create a
   *         {@link net.sf.mmm.security.api.hash.SecurityHashCreator#hash() hash} that is then signed using the
   *         configured cryptographic algorithm.
   */
  SecuritySignatureFactory signUsingCryptor(SecurityHashFactory hashFactory);

  /**
   * @return the {@link SecuritySignatureFactory} combining the {@link net.sf.mmm.security.api.hash.SecurityHashFactory}
   *         in advance to create a {@link net.sf.mmm.security.api.hash.SecurityHashCreator#hash() hash} that is then
   *         signed using the configured cryptographic algorithm (e.g. the
   *         {@link net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPrivatePublic}).
   */
  SecuritySignatureFactory signUsingHashAndCryptor();

}
