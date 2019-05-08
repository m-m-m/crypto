package net.sf.mmm.security.api.hash.access;

import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityAccessHash} for {@code MD5}. <br>
 * <b>ATTENTION:</b><br>
 * Please note that MD5 is a weak hash algorithm that shall not be used for secure hashing (e.g. for signing).
 *
 * @since 1.0.0
 */
public class SecurityAccessMd5 extends SecurityAccessHash {

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   * @param iterationCount the {@link SecurityHashConfig#getIterationCount() iteration count}.
   */
  public SecurityAccessMd5(SecurityProvider provider, int iterationCount) {

    super(new SecurityHashConfig("MD5", provider, iterationCount));
  }

  /**
   * @return new default instance.
   */
  public static SecurityAccessMd5 of() {

    return of(1);
  }

  /**
   * @param iterationCount the {@link SecurityHashConfig#getIterationCount() iteration count}.
   * @return new instance with the given {@link SecurityHashConfig#getIterationCount() iteration count}.
   */
  public static SecurityAccessMd5 of(int iterationCount) {

    return new SecurityAccessMd5(null, iterationCount);
  }

}
