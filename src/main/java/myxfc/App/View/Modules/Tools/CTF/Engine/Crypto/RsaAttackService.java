package myxfc.App.View.Modules.Tools.CTF.Engine.Crypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class RsaAttackService {
    public record Factors(BigInteger p, BigInteger q) {
    }

    public static BigInteger smallExponentDecrypt(BigInteger ciphertext, BigInteger exponent) {
        BigInteger plaintext = integerRoot(ciphertext, exponent.intValueExact());
        return plaintext.pow(exponent.intValueExact()).equals(ciphertext) ? plaintext : null;
    }

    public static BigInteger commonModulusDecrypt(BigInteger n, BigInteger e1, BigInteger c1,
                                                  BigInteger e2, BigInteger c2) {
        BigInteger[] coefficients = extendedGcd(e1, e2);
        if (!coefficients[0].equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("Public exponents must be coprime");
        }
        BigInteger first = signedPow(c1, coefficients[1], n);
        BigInteger second = signedPow(c2, coefficients[2], n);
        return first.multiply(second).mod(n);
    }

    public static Factors recoverFromPrivateExponent(BigInteger n, BigInteger e, BigInteger d) {
        BigInteger k = e.multiply(d).subtract(BigInteger.ONE);
        int s = k.getLowestSetBit();
        BigInteger r = k.shiftRight(s);
        SecureRandom random = new SecureRandom();
        for (int attempt = 0; attempt < 200; attempt++) {
            BigInteger g = new BigInteger(n.bitLength(), random);
            if (g.compareTo(BigInteger.TWO) < 0 || g.compareTo(n.subtract(BigInteger.ONE)) >= 0) {
                continue;
            }
            BigInteger x = g.modPow(r, n);
            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) {
                continue;
            }
            for (int i = 0; i < s; i++) {
                BigInteger y = x.multiply(x).mod(n);
                if (y.equals(BigInteger.ONE)) {
                    BigInteger p = x.subtract(BigInteger.ONE).gcd(n);
                    if (isFactor(n, p)) {
                        return ordered(p, n.divide(p));
                    }
                }
                if (y.equals(n.subtract(BigInteger.ONE))) {
                    break;
                }
                x = y;
            }
        }
        throw new IllegalArgumentException("Unable to factor RSA modulus from the supplied values");
    }

    public static BigInteger wienerAttack(BigInteger n, BigInteger e) {
        BigInteger[] continued = continuedFraction(e, n);
        BigInteger previousP = BigInteger.ZERO;
        BigInteger previousQ = BigInteger.ONE;
        BigInteger currentP = BigInteger.ONE;
        BigInteger currentQ = BigInteger.ZERO;
        for (BigInteger coefficient : continued) {
            BigInteger nextP = coefficient.multiply(currentP).add(previousP);
            BigInteger nextQ = coefficient.multiply(currentQ).add(previousQ);
            BigInteger d = nextQ;
            BigInteger k = nextP;
            if (k.signum() > 0 && e.multiply(d).subtract(BigInteger.ONE).mod(k).equals(BigInteger.ZERO)) {
                BigInteger phi = e.multiply(d).subtract(BigInteger.ONE).divide(k);
                BigInteger sum = n.subtract(phi).add(BigInteger.ONE);
                BigInteger discriminant = sum.multiply(sum).subtract(n.shiftLeft(2));
                if (discriminant.signum() >= 0) {
                    BigInteger root = integerSqrt(discriminant);
                    if (root.multiply(root).equals(discriminant)
                            && sum.add(root).mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
                        return d;
                    }
                }
            }
            previousP = currentP;
            previousQ = currentQ;
            currentP = nextP;
            currentQ = nextQ;
        }
        throw new IllegalArgumentException("Wiener attack did not recover a private exponent");
    }

    public static BigInteger privateExponent(BigInteger p, BigInteger q, BigInteger e) {
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        return e.modInverse(phi);
    }

    public static BigInteger privateExponentFromDp(BigInteger n, BigInteger p, BigInteger e, BigInteger dp) {
        if (!n.mod(p).equals(BigInteger.ZERO) || !e.multiply(dp).mod(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("Invalid n, p, e and dp values");
        }
        return privateExponent(p, n.divide(p), e);
    }

    public static BigInteger crtDecrypt(BigInteger ciphertext, BigInteger p, BigInteger q,
                                        BigInteger dp, BigInteger dq) {
        BigInteger m1 = ciphertext.modPow(dp, p);
        BigInteger m2 = ciphertext.modPow(dq, q);
        BigInteger coefficient = q.modInverse(p);
        BigInteger h = coefficient.multiply(m1.subtract(m2)).mod(p);
        return m2.add(h.multiply(q)).mod(p.multiply(q));
    }

    private static BigInteger[] continuedFraction(BigInteger numerator, BigInteger denominator) {
        List<BigInteger> values = new ArrayList<>();
        while (!denominator.equals(BigInteger.ZERO)) {
            BigInteger[] division = numerator.divideAndRemainder(denominator);
            values.add(division[0]);
            numerator = denominator;
            denominator = division[1];
        }
        return values.toArray(BigInteger[]::new);
    }

    private static BigInteger[] extendedGcd(BigInteger a, BigInteger b) {
        BigInteger oldR = a;
        BigInteger r = b;
        BigInteger oldS = BigInteger.ONE;
        BigInteger s = BigInteger.ZERO;
        BigInteger oldT = BigInteger.ZERO;
        BigInteger t = BigInteger.ONE;
        while (!r.equals(BigInteger.ZERO)) {
            BigInteger quotient = oldR.divide(r);
            BigInteger next = oldR.subtract(quotient.multiply(r));
            oldR = r;
            r = next;
            next = oldS.subtract(quotient.multiply(s));
            oldS = s;
            s = next;
            next = oldT.subtract(quotient.multiply(t));
            oldT = t;
            t = next;
        }
        return new BigInteger[]{oldR, oldS, oldT};
    }

    private static BigInteger signedPow(BigInteger value, BigInteger exponent, BigInteger modulus) {
        return exponent.signum() < 0 ? value.modInverse(modulus).modPow(exponent.negate(), modulus)
                : value.modPow(exponent, modulus);
    }

    private static BigInteger integerRoot(BigInteger value, int degree) {
        if (degree <= 0) {
            throw new IllegalArgumentException("Degree must be positive");
        }
        BigInteger low = BigInteger.ZERO;
        BigInteger high = BigInteger.ONE;
        while (high.pow(degree).compareTo(value) <= 0) {
            high = high.shiftLeft(1);
        }
        while (low.add(BigInteger.ONE).compareTo(high) < 0) {
            BigInteger middle = low.add(high).shiftRight(1);
            if (middle.pow(degree).compareTo(value) <= 0) {
                low = middle;
            } else {
                high = middle;
            }
        }
        return low;
    }

    private static BigInteger integerSqrt(BigInteger value) {
        if (value.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger x = BigInteger.ONE.shiftLeft((value.bitLength() + 1) / 2);
        while (true) {
            BigInteger next = x.add(value.divide(x)).shiftRight(1);
            if (next.compareTo(x) >= 0) {
                return x;
            }
            x = next;
        }
    }

    private static boolean isFactor(BigInteger n, BigInteger candidate) {
        return candidate.compareTo(BigInteger.ONE) > 0 && candidate.compareTo(n) < 0
                && n.mod(candidate).equals(BigInteger.ZERO);
    }

    private static Factors ordered(BigInteger first, BigInteger second) {
        return first.compareTo(second) <= 0 ? new Factors(first, second) : new Factors(second, first);
    }
}
