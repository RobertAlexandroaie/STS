/**
 * 
 */
package util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * @author Robert
 */
public class Generator {
    private static Generator instance = null;

    private static BigInteger p;
    private static BigInteger q;
    private static BigInteger alpha;

    private Generator() {
	genP();
	genAlpha();
    }

    public static Generator getInstance() {
	if (instance == null) {
	    instance = new Generator();
	}
	return instance;
    }

    private BigInteger genAlpha() {
	BigInteger one = new BigInteger("1");
	BigInteger two = new BigInteger("2");
	Random random = new SecureRandom();

	boolean ok = false;

	do {
	    alpha = new BigInteger(512, random);
	    BigInteger pow1 = alpha.modPow(q, p);
	    BigInteger pow2 = alpha.modPow(two, p);
	    if (pow1.compareTo(one) != 0 && pow2.compareTo(one) != 0) {
		ok = true;
	    }

	} while (alpha.compareTo(p.subtract(two)) > 0 || alpha.compareTo(two) < 0 || !ok);

	return alpha;
    }

    public static BigInteger genP() {
	Random random = new SecureRandom();

	BigInteger one = new BigInteger("1");
	BigInteger two = new BigInteger("2");

	do {
	    q = BigInteger.probablePrime(512, random);
	    p = q.multiply(two).add(one);
	} while (!p.isProbablePrime(512));

	return p;
    }

    /**
     * @return the p
     */
    public static BigInteger getP() {
	return p;
    }

    /**
     * @return the alpha
     */
    public static BigInteger getAlpha() {
	return alpha;
    }

    /**
     * @return the q
     */
    public static BigInteger getQ() {
	return q;
    }

}
