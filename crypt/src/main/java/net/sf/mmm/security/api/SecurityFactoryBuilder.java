package net.sf.mmm.security.api;

import net.sf.mmm.security.api.cert.SecurityCertificateFactoryBuilder;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactoryBuilder;
import net.sf.mmm.security.api.hash.SecurityHashFactoryBuilder;
import net.sf.mmm.security.api.key.SecurityKeyFactoryBuilder;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreFactoryBuilder;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;
import net.sf.mmm.security.api.provider.SecurityProviderBuilder;
import net.sf.mmm.security.api.random.AbstractSecurityRandomFactoryBuilder;
import net.sf.mmm.security.api.sign.SecuritySignatureFactoryBuilder;

/**
 * Interface to build all {@link AbstractSecurityFactory security factories}. This is a stateful object and therefore
 * <b>not</b> thread-safe. However, the returned {@link AbstractSecurityFactory factories} are thread-safe. To get an
 * instance of {@link SecurityFactoryBuilder} use {@link SecurityBuilder#newFactoryBuilder()}.<br>
 * The following types of methods are available:<br>
 * <table border="1">
 * <tr>
 * <th>{@link AbstractSecurityFactory Factory}</th>
 * <th>build method</th>
 * <th>Get factory</th>
 * <th>Dependency</th>
 * </tr>
 * <tr>
 * <td>{@link net.sf.mmm.security.api.random.SecurityRandomFactory}</td>
 * <td>{@link #random(net.sf.mmm.security.api.random.SecurityRandomConfig) random}</td>
 * <td>{@link #getRandomFactory()}</td>
 * <td>-</td>
 * </tr>
 * <tr>
 * <td>{@link net.sf.mmm.security.api.hash.SecurityHashFactory}</td>
 * <td>{@link #hash(net.sf.mmm.security.api.hash.SecurityHashConfig) hash}</td>
 * <td>{@link #getHashFactory()}</td>
 * <td>-</td>
 * </tr>
 * <tr>
 * <td>{@link net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryBidirectional}</td>
 * <td>{@link #crypt(net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigBidirectional)
 * crypt}</td>
 * <td rowspan=4>{@link #getCryptorFactory()}</td>
 * <td rowspan=4>{@link net.sf.mmm.security.api.random.SecurityRandomFactory}</td>
 * </tr>
 * <tr>
 * <td>{@link net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPrivatePublic}</td>
 * <td>{@link #crypt(net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPrivatePublic)
 * crypt}</td>
 * </tr>
 * <tr>
 * <td>{@link net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPublicPrivate}</td>
 * <td>{@link #crypt(net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPublicPrivate)
 * crypt}</td>
 * </tr>
 * <tr>
 * <td>{@link net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorFactory}</td>
 * <td>{@link #crypt(net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorConfig) crypt}</td>
 * </tr>
 * <tr>
 * <td rowspan=3>{@link net.sf.mmm.security.api.sign.SecuritySignatureFactory}</td>
 * <td>{@link #sign(net.sf.mmm.security.api.sign.SecuritySignatureConfig) sign}</td>
 * <td rowspan=3>{@link #getSignatureFactory()}</td>
 * <td>{@link net.sf.mmm.security.api.random.SecurityRandomFactory}</td>
 * </tr>
 * <tr>
 * <td>{@link #signUsingHash(net.sf.mmm.security.api.sign.SecuritySignatureConfig) signUsingHash}</td>
 * <td>{@link net.sf.mmm.security.api.random.SecurityRandomFactory},
 * {@link net.sf.mmm.security.api.hash.SecurityHashFactory}</td>
 * </tr>
 * <tr>
 * <td>{@link #signUsingHashAndCryptor() signUsingHashAndCryptor}</td>
 * <td>{@link net.sf.mmm.security.api.random.SecurityRandomFactory},
 * {@link net.sf.mmm.security.api.hash.SecurityHashFactory},
 * {@link net.sf.mmm.security.api.crypt.SecurityCryptorFactory}</td>
 * </tr>
 * <tr>
 * <td>{@link net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory}</td>
 * <td>{@link #key(net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig) key}</td>
 * <td>{@link #getAsymmetricKeyFactory()}</td>
 * <td>{@link net.sf.mmm.security.api.random.SecurityRandomFactory}</td>
 * </tr>
 * <tr>
 * <td>{@link net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactory}</td>
 * <td>{@link #key(net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfig) key}</td>
 * <td>{@link #getSymmetricKeyFactory()}</td>
 * <td>-</td>
 * </tr>
 * </table>
 * All these build methods will use the {@link java.security.Provider} previously configured by {@link #provider()},
 * {@link #provider(String)}, or {@link #provider(java.security.Provider)}. These {@code provider} method return the
 * {@link SecurityFactoryBuilder} itself for fluent method calls. If no {@link java.security.Provider} is configured the
 * default is used - see {@link #provider()} for details and to reset to that behavior.<br>
 *
 * @see SecurityBuilder#newFactoryBuilder()
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityFactoryBuilder extends AbstractSecurityRandomFactoryBuilder<SecurityFactoryBuilder>,
    AbstractSecurityGetProvider, SecurityProviderBuilder<SecurityFactoryBuilder>, SecurityHashFactoryBuilder,
    SecurityCryptorFactoryBuilder, SecurityKeyFactoryBuilder, SecuritySignatureFactoryBuilder,
    SecurityKeyStoreFactoryBuilder, SecurityCertificateFactoryBuilder, AbstractSecurityFactories {

}
