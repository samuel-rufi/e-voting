package crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

public class BlindedRSA {

	public static AsymmetricCipherKeyPair generateKeys(int keySize) {
		RSAKeyPairGenerator r = new RSAKeyPairGenerator();

		r.init(new RSAKeyGenerationParameters(new BigInteger("10001", 16), new SecureRandom(), keySize, 80));

		AsymmetricCipherKeyPair keys = r.generateKeyPair();

		return keys;
	}

	public static BigInteger generateBlindingFactor(CipherParameters pubKey) {
		RSABlindingFactorGenerator gen = new RSABlindingFactorGenerator();

		gen.init(pubKey);

		return gen.generateBlindingFactor();
	}

	public static byte[] blind(CipherParameters key, BigInteger factor, byte[] msg) {
		RSABlindingEngine eng = new RSABlindingEngine();

		RSABlindingParameters params = new RSABlindingParameters((RSAKeyParameters) key, factor);
		PSSSigner blindSigner = new PSSSigner(eng, new SHA1Digest(), 15);
		blindSigner.init(true, params);

		blindSigner.update(msg, 0, msg.length);

		byte[] blinded = null;
		try {
			blinded = blindSigner.generateSignature();
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return blinded;
	}

	public static byte[] unblind(CipherParameters key, BigInteger factor, byte[] msg) {
		RSABlindingEngine eng = new RSABlindingEngine();

		RSABlindingParameters params = new RSABlindingParameters((RSAKeyParameters) key, factor);
		eng.init(false, params);

		return eng.processBlock(msg, 0, msg.length);
	}

	public static byte[] sign(CipherParameters key, byte[] toSign) {
		SHA1Digest dig = new SHA1Digest();
		RSAEngine eng = new RSAEngine();

		PSSSigner signer = new PSSSigner(eng, dig, 15);
		signer.init(true, key);
		signer.update(toSign, 0, toSign.length);

		byte[] sig = null;

		try {
			sig = signer.generateSignature();
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return sig;
	}

	public static boolean verify(CipherParameters key, byte[] msg, byte[] sig) {
		PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA1Digest(), 15);
		signer.init(false, key);

		signer.update(msg, 0, msg.length);

		return signer.verifySignature(sig);
	}

	public static byte[] signBlinded(CipherParameters key, byte[] msg) {
		RSAEngine signer = new RSAEngine();
		signer.init(true, key);
		return signer.processBlock(msg, 0, msg.length);
	}

	public static void main(String[] args) {
		AsymmetricCipherKeyPair bob_keyPair = BlindedRSA.generateKeys(1024);
		AsymmetricCipherKeyPair alice_keyPair = BlindedRSA.generateKeys(1024);

		try {
			byte[] msg = "OK".getBytes("UTF-8");

			// ----------- Bob: Generating blinding factor based on Alice's public key
			// -----------//
			BigInteger blindingFactor = BlindedRSA.generateBlindingFactor(alice_keyPair.getPublic());

			// ----------------- Bob: Blinding message with Alice's public key
			// -----------------//
			byte[] blinded_msg = BlindedRSA.blind(alice_keyPair.getPublic(), blindingFactor, msg);

			// ------------- Bob: Signing blinded message with Bob's private key
			// -------------//
			byte[] sig = BlindedRSA.sign(bob_keyPair.getPrivate(), blinded_msg);

			// ------------- Alice: Verifying Bob's signature -------------//
			if (BlindedRSA.verify(bob_keyPair.getPublic(), blinded_msg, sig)) {

				// ---------- Alice: Signing blinded message with Alice's private key
				// ----------//
				byte[] sigByAlice = BlindedRSA.signBlinded(alice_keyPair.getPrivate(), blinded_msg);

				// ------------------- Bob: Unblinding Alice's signature -------------------//
				byte[] unblindedSigByAlice = BlindedRSA.unblind(alice_keyPair.getPublic(), blindingFactor, sigByAlice);

				// ---------------- Bob: Verifying Alice's unblinded signature
				// ----------------//
				System.out.println(BlindedRSA.verify(alice_keyPair.getPublic(), msg, unblindedSigByAlice));
				// Now Bob has Alice's signature for the original message
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}