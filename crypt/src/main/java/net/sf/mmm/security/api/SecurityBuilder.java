package net.sf.mmm.security.api;

/**
 * Interface to {@link #newFactoryBuilder() create a new} {@link SecurityFactoryBuilder}. The Implementation is
 * thread-safe and builds the entry point to the entire security API of this library. Once you have an instance of this
 * interface you can configure and retrieve everything else via the API ({@link net.sf.mmm.security.api} and
 * its sub-packages) without depending on implementation specific details.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityBuilder {

  /**
   * @return a new {@link SecurityFactoryBuilder} instance.
   */
  SecurityFactoryBuilder newFactoryBuilder();

}
