package net.sf.mmm.crypto.symmetric.key;

import net.sf.mmm.crypto.AbstractCryptoFactory;
import net.sf.mmm.crypto.key.KeyCreatorFactory;

/**
 * Interface for a {@link AbstractCryptoFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link SymmetricKeyCreator} for symmetric cryptographic keys.<br>
 * An instance of {@link SymmetricKeyCreatorFactory} therefore represents a configuration with specific
 * {@link java.security.Key} {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat()
 * format}(s).
 *
 * @param <C> type of {@link SymmetricKeyCreator}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SymmetricKeyCreatorFactory<C extends SymmetricKeyCreator<?>> extends KeyCreatorFactory {

  @Override
  C newKeyCreator();

}
