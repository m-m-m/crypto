package net.sf.mmm.crypto.hash;

import net.sf.mmm.crypto.AbstractCryptoFactory;

/**
 * Interface for a {@link AbstractCryptoFactory factory} to {@link #newHashCreator() create} instances of
 * {@link HashCreator}. An instance of {@link HashFactory} therefore represents a specific configuration
 * (see {@link HashConfig}) based on an {@link HashConfig#getAlgorithm() hash algorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface HashFactory extends AbstractCryptoFactory {

  /**
   * @return a new instance of {@link HashCreator} for the configured hash algorithm of this factory.
   */
  HashCreator newHashCreator();

}
