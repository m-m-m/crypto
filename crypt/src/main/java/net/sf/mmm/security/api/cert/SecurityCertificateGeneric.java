package net.sf.mmm.security.api.cert;

import java.security.cert.Certificate;
import java.util.function.Supplier;

import net.sf.mmm.util.datatype.api.BinaryType;

/**
 * Generic implementation of {@link SecurityCertificate}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCertificateGeneric extends BinaryType implements SecurityCertificate {

  private Certificate certificate;

  private Supplier<Certificate> certificateSupplier;

  /**
   * The constructor.
   *
   * @param certificate the {@link #getCertificate() certificate} to wrap.
   */
  public SecurityCertificateGeneric(Certificate certificate) {

    this(encode(certificate), certificate);
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data} of the {@link Certificate#getEncoded() encoded}
   *        {@link Certificate}.
   * @param certificate the {@link #getCertificate() certificate} to wrap.
   */
  public SecurityCertificateGeneric(byte[] data, Certificate certificate) {

    super(data);
    this.certificate = certificate;
    this.certificateSupplier = null;
  }

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data} of the {@link Certificate#getEncoded() encoded}
   *        {@link Certificate}.
   * @param certificateSupplier the {@link Supplier} of the {@link #getCertificate() certificate}.
   */
  public SecurityCertificateGeneric(byte[] data, Supplier<Certificate> certificateSupplier) {

    super(data);
    this.certificate = null;
    this.certificateSupplier = certificateSupplier;
  }

  /**
   * The constructor.
   *
   * @param hex the {@link #getData() data} as {@link #getHex() hex} of the {@link Certificate#getEncoded() encoded}
   *        {@link Certificate}.
   * @param certificate the {@link #getCertificate() certificate} to wrap.
   */
  public SecurityCertificateGeneric(String hex, Certificate certificate) {

    super(hex);
    this.certificate = certificate;
    this.certificateSupplier = null;
  }

  /**
   * The constructor.
   *
   * @param hex the {@link #getData() data} as {@link #getHex() hex} of the {@link Certificate#getEncoded() encoded}
   *        {@link Certificate}.
   * @param certificateSupplier the {@link Supplier} of the {@link #getCertificate() certificate}.
   */
  public SecurityCertificateGeneric(String hex, Supplier<Certificate> certificateSupplier) {

    super(hex);
    this.certificate = null;
    this.certificateSupplier = certificateSupplier;
  }

  private static byte[] encode(Certificate certificate) {

    try {
      return certificate.getEncoded();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to serialize certificate of type " + certificate.getType() + "!", e);
    }
  }

  @Override
  public Certificate getCertificate() {

    if ((this.certificate == null) && (this.certificateSupplier != null)) {
      this.certificate = this.certificateSupplier.get();
      this.certificateSupplier = null;
    }
    return this.certificate;
  }

}
