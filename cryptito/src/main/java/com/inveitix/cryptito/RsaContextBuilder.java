package com.inveitix.cryptito;

/**
 * Used to build an {@link com.inveitix.cryptito.RsaContext}.
 */
public class RsaContextBuilder
{
    private RsaContext.Algorithm algorithm = RsaContext.Algorithm.RSA;
    private RsaContext.Mode mode = RsaContext.Mode.ECB;
    private RsaContext.Padding padding = RsaContext.Padding.OAEP_WITH_SHA1_AND_MGF1_PADDING;
    private RsaContext.KeyLength keyLength = RsaContext.KeyLength.BITS_2048;

    /**
     * Sets the cipher algorithm. Defaults to {@code AES} and is the only supported algorithm
     *
     * @param algorithm the {@link com.inveitix.cryptito.RsaContext.Algorithm}
     * @return {@link com.inveitix.cryptito.RsaContextBuilder}
     */
    public RsaContextBuilder setAlgorithm(RsaContext.Algorithm algorithm)
    {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Sets the cipher algorithm mode. Defaults to {@code ECB}
     *
     * @param mode the {@link com.inveitix.cryptito.RsaContext.Mode}
     * @return {@link com.inveitix.cryptito.RsaContextBuilder}
     */
    public RsaContextBuilder setMode(RsaContext.Mode mode)
    {
        this.mode = mode;
        return this;
    }

    /**
     * Sets the cipher algorithm padding. Defaults to {@code NoPadding}
     *
     * @param padding the {@link com.inveitix.cryptito.RsaContext.Padding}
     * @return {@link com.inveitix.cryptito.RsaContextBuilder}
     */
    public RsaContextBuilder setPadding(RsaContext.Padding padding)
    {
        this.padding = padding;
        return this;
    }

    /**
     * Sets the cipher key length. Defaults to {@code 2048}
     *
     * @param keyLength the {@link com.inveitix.cryptito.RsaContext.KeyLength}
     * @return {@link com.inveitix.cryptito.RsaContextBuilder}
     */
    public RsaContextBuilder setKeyLength(RsaContext.KeyLength keyLength)
    {
        this.keyLength = keyLength;
        return this;
    }

    /**
     * Creates an {@link com.inveitix.cryptito.RsaContext} with the arguments supplied to this builder.
     *
     * @return {@link com.inveitix.cryptito.RsaContext}
     */
    public RsaContext build()
    {
        return new RsaContext(algorithm, mode, padding, keyLength);
    }
}