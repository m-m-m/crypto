package net.sf.mmm.security.api.sign;

import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactory;
import net.sf.mmm.security.api.hash.SecurityHashFactory;

/**
 * Interface to {@link #sign(SecuritySignatureConfig) create} a {@link SecuritySignatureFactory}.
 *
 * @see net.sf.mmm.security.api.SecurityBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureFactoryBuilder extends AbstractSecuritySignatureFactoryBuilder {

  /**
   * @param configuration the {@link SecuritySignatureConfig}.
   * @return the {@link SecuritySignatureFactory} for the given {@code configuration}.
   */
  SecuritySignatureFactory sign(SecuritySignatureConfig configuration);

  /**
   * @param configuration the {@link SecuritySignatureConfig}.
   * @param hashFactory the {@link SecurityHashFactory} that is used in advance to build a hash that is then signed
   *        using the given {@link SecuritySignatureConfig}.
   * @return the {@link SecuritySignatureFactory} for the given {@code configuration} and {@code hashFactory}.
   */
  SecuritySignatureFactory sign(SecuritySignatureConfig configuration, SecurityHashFactory hashFactory);

  /**
   * @param configuration the {@link SecuritySignatureConfig}.
   * @param hashFactory the {@link SecurityHashFactory} that is used in advance to build a hash that is then signed
   *        using the given {@link SecuritySignatureConfig}.
   * @return the {@link SecuritySignatureFactory} for the given {@code configuration} and {@code hashFactory}.
   */
  SecuritySignatureFactory signUsingHash(SecuritySignatureConfig configuration);

  /**
   * @param hashFactory the {@link SecurityHashFactory} that is used in advance to build a hash that is then signed
   *        using the given {@link SecurityAsymmetricCryptorFactory} to encrypt the hash.
   * @param cryptorFactory the {@link SecurityCryptorFactory} used to encrypt the hash for signing and decrypt it for
   *        verification.
   * @return the {@link SecuritySignatureFactory} for the given {@code configuration}
   */
  SecuritySignatureFactory sign(SecurityHashFactory hashFactory, SecurityAsymmetricCryptorFactory cryptorFactory);

}
