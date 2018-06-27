package com.inveitix.cryptito;

/**
 * Context passed into {@link com.inveitix.cryptito.RsaCipher}. You should use {@link RsaContextBuilder}
 * to create this class as it contains many defaults.
 */
public class RsaContext
{
    private Algorithm algorithm;
    private Mode mode;
    private Padding padding;
    private KeyLength keyLength;

    /**
     * Initializes a new {@code RsaContext} for use with {@link com.inveitix.cryptito.RsaCipher}. Most of the inputs are
     * described in the <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html">
     * Java Cryptography Architecture Standard Algorithm Name Documentation for JDK 8</a>.
     *
     * @param algorithm the {@link Algorithm}
     * @param mode      the {@link Mode}
     * @param padding   the {@link Padding}
     * @param keyLength the {@link KeyLength}
     */
    @SuppressWarnings("WeakerAccess")
    public RsaContext(Algorithm algorithm,
                      Mode mode,
                      Padding padding,
                      KeyLength keyLength)
    {
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
        this.keyLength = keyLength;
    }

    @SuppressWarnings("WeakerAccess")
    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    @SuppressWarnings("WeakerAccess")
    public Mode getMode()
    {
        return mode;
    }

    @SuppressWarnings("WeakerAccess")
    public Padding getPadding()
    {
        return padding;
    }

    @SuppressWarnings("WeakerAccess")
    public KeyLength getKeyLength()
    {
        return keyLength;
    }

    /**
     * Algorithm used for the {@link javax.crypto.Cipher}
     */
    public enum Algorithm
    {
        RSA("RSA");;

        private String value;

        Algorithm(String value)
        {
            this.value = value;
        }

        @Override
        public String toString()
        {
            return value;
        }
    }

    /**
     * Mode used for the {@link javax.crypto.Cipher}
     */
    public enum Mode
    {
        /**
         * No Modes
         */
        NONE("NONE"),

        /**
         * Electronic Codebook Mode, as defined in <a href="http://csrc.nist.gov/publications/fips/fips81/fips81.htm">
         * FIPS PUB 81</a>
         */
        ECB("ECB");

        private String value;

        Mode(String value)
        {
            this.value = value;
        }

        @Override
        public String toString()
        {
            return value;
        }
    }

    /**
     * Cipher algorithm padding
     */
    public enum Padding
    {
        NO_PADDING("NoPadding"),
        OAEP_PADDING("OAEPPadding"),
        PKCS1_PADDING("PKCS1Padding"),
        OAEP_WITH_SHA256_AND_MGF1_PADDING("OAEPwithSHA256andMGF1Padding"),
        OAEP_WITH_SHA224_AND_MGF1_PADDING("OAEPwithSHA224andMGF1Padding"),
        OAEP_WITH_SHA384_AND_MGF1_PADDING("OAEPwithSHA384andMGF1Padding"),
        OAEP_WITH_SHA512_AND_MGF1_PADDING("OAEPwithSHA512andMGF1Padding"),
        OAEP_WITH_SHA1_AND_MGF1_PADDING("OAEPWithSHA1AndMGF1Padding");

        private String value;

        Padding(String value)
        {
            this.value = value;
        }

        @Override
        public String toString()
        {
            return value;
        }
    }

    /**
     * Cipher key length
     */
    public enum KeyLength
    {
        BITS_1024(1024),
        BITS_2048(2048),
        BITS_4096(4096),
        BITS_512(512);

        private int bits;

        KeyLength(int bits)
        {
            this.bits = bits;
        }

        public int bits()
        {
            return bits;
        }

        public int bytes()
        {
            return bits >> 3;
        }
    }
}
