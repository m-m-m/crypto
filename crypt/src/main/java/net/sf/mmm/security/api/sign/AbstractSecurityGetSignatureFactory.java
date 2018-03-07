package net.sf.mmm.security.api.sign;

/**
 * Abstract interface to {@link #getSignatureFactory() get} the {@link SecuritySignatureFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetSignatureFactory {

  /**
   * @return the {@link SecuritySignatureFactory}.
   */
  SecuritySignatureFactory getSignatureFactory();

  /**
   * @throws IllegalStateException if {@link #getSignatureFactory()} is {@code null}.
   * @return the {@link SecuritySignatureFactory}. Never {@code null}.
   */
  default SecuritySignatureFactory getSignatureFactoryRequired() {

    SecuritySignatureFactory factory = getSignatureFactory();
    if (factory == null) {
      throw new IllegalStateException("SignatureFactory is not available!");
    }
    return factory;
  }
}
