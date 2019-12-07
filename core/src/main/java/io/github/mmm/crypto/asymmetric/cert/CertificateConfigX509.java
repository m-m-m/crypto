package io.github.mmm.crypto.asymmetric.cert;

import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * {@link CertificateConfig} for {@value #TYPE_X509}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class CertificateConfigX509 extends CertificateConfig {

  /** {@link #getType() Type} for <a href="https://en.wikipedia.org/wiki/X.509">X.509</a>. */
  public static final String TYPE_X509 = "X509";

  /**
   * The constructor.
   */
  public CertificateConfigX509() {

    this(null);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   */
  public CertificateConfigX509(SecurityProvider provider) {

    super(TYPE_X509, provider);
  }

}
