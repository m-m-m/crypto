package net.sf.mmm.crypto.asymmetric.key;

import net.sf.mmm.crypto.AbstractCryptoFactory;
import net.sf.mmm.crypto.key.KeyCreator;
import net.sf.mmm.crypto.key.KeyFactory;

/**
 * Interface for a {@link AbstractCryptoFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link KeyCreator} for asymmetric cryptographic keys.<br>
 * An instance of {@link AsymmetricKeyFactory} therefore represents a configuration with specific
 * {@link java.security.Key} {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat()
 * format}(s).
 *
 * @param <K> type of {@link AsymmetricKeyCreator}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AsymmetricKeyFactory<K extends AsymmetricKeyCreator<?, ?, ?>> extends KeyFactory {

  @Override
  K newKeyCreator();

}
