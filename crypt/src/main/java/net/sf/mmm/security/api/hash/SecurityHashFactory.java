package net.sf.mmm.security.api.hash;

import net.sf.mmm.security.api.AbstractSecurityFactory;

/**
 * Interface for a {@link AbstractSecurityFactory factory} to {@link #newHashCreator() create} instances of
 * {@link SecurityHashCreator}. An instance of {@link SecurityHashFactory} therefore represents a specific configuration
 * (see {@link SecurityHashConfig}) based on an {@link SecurityHashConfig#getAlgorithm() hash
 * algorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityHashFactory extends AbstractSecurityFactory {

  /** {@link #getType() Type} of this factory. */
  public static final String TYPE = "HashFactory";

  /**
   * @return a new instance of {@link SecurityHashCreator} for the configured hash algorithm of this factory.
   */
  SecurityHashCreator newHashCreator();

  @Override
  default String getType() {

    return TYPE;
  }

}
