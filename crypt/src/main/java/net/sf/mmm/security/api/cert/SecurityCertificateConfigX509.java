package net.sf.mmm.security.api.cert;

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
    super(TYPE_X509);
  }

}
