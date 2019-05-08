package net.sf.mmm.security.api.asymmetric.sign;

/**
 * Interface for factory to create instances of {@link SecuritySignature}. It is only relevant for internal usage and as
 * SPI. End-users should look at {@link SecuritySignatureProcessorFactory}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @since 1.0.0
 */
public interface SecuritySignatureFactory<S extends SecuritySignature> {

  /**
   * @param data the {@link SecuritySignature#getData() binary signature data}.
   * @return the deserialized {@link SecuritySignature}.
   */
  S createSignature(byte[] data);

}
