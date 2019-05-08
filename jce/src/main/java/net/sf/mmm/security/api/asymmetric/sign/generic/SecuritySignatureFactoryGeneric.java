package net.sf.mmm.security.api.asymmetric.sign.generic;

import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureFactory;

/**
 * Implementation of {@link SecuritySignatureFactory} for {@link SecuritySignatureGeneric}.
 *
 * @since 1.0.0
 */
public class SecuritySignatureFactoryGeneric implements SecuritySignatureFactory<SecuritySignatureGeneric> {

  /** The singleton instance. */
  public static final SecuritySignatureFactoryGeneric INSTANCE = new SecuritySignatureFactoryGeneric();

  @Override
  public SecuritySignatureGeneric createSignature(byte[] data) {

    return new SecuritySignatureGeneric(data);
  }

}
