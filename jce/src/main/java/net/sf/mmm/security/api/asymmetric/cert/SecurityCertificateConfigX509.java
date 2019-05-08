package net.sf.mmm.security.api.asymmetric.cert;

import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityCertificateConfig} for {@value #TYPE_X509}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCertificateConfigX509 extends SecurityCertificateConfig {

  /** {@link #getType() Type} for <a href="https://en.wikipedia.org/wiki/X.509">X.509</a>. */
  public static final String TYPE_X509 = "X509";

  /**
   * The constructor.
   */
  public SecurityCertificateConfigX509() {

    this(null);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   */
  public SecurityCertificateConfigX509(SecurityProvider provider) {

    super(TYPE_X509, provider);
  }

}
