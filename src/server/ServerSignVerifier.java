package server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class ServerSignVerifier {

	private static PrivateKey privateKeyServ;
	private static PublicKey publicKey;
	private static PublicKey publicKeyTSA;
	private static byte[] sign;
	byte[] encoding;
	private static String pathToKeyStore;
	private static String pathToTrustStore;

	public ServerSignVerifier(String path1, String path2) {
		pathToKeyStore = path1;
		pathToTrustStore = path2;
	}

	public void ServerSign(byte[] doc) {
		try {
			String algorithm;
			int blockSize;
			byte block[] = new byte[1024];

			PrivateKey();
			ByteArrayInputStream msg = new ByteArrayInputStream(doc);
			algorithm = privateKeyServ.getAlgorithm().equalsIgnoreCase("RSA") ? "MD5withRSA" : "SHA1withDSA";

			Signature signer = Signature.getInstance(algorithm);
			signer.initSign(privateKeyServ);
			while ((blockSize = msg.read(block)) > 0) {
				signer.update(block, 0, blockSize);
			}
			sign = signer.sign();
			System.out.println("Doc signed, sign: \n\t");
			for (int i = 0; i < sign.length; i++) {
				System.out.print(sign[i] + " ");
			}
			msg.close();

		} catch (InvalidKeyException | SignatureException | IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	public byte[] getServerSign() {
		return sign;
	}

	public boolean VerifyClientSign(byte[] sigClient, byte[] clientSign)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		String algorithm;
		int blockSize;
		byte block[] = new byte[1024];

		System.out.println("Verifying client: ");
		ByteArrayInputStream validate = new ByteArrayInputStream(sigClient);
		PublicKey();
		algorithm = publicKey.getAlgorithm().equalsIgnoreCase("RSA") ? "MD5withRSA" : "SHA1withDSA";

		Signature verifier = Signature.getInstance(algorithm);
		verifier.initVerify(publicKey);
		while ((blockSize = validate.read(block)) > 0) {
			verifier.update(block, 0, blockSize);
		}
		validate.close();

		boolean toRet = verifier.verify(clientSign);
		String toPrint = toRet ? "\tValid\n" : "\t Not valid\n";
		System.out.println(toPrint);
		return toRet;
	}

	public byte[] CypherDoc(byte[] doc, String cypherAlgorithm) throws KeyStoreException, IOException,
			CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidKeyException,
			NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

		KeyStore keyStores;
		char[] pass = "123456".toCharArray();
		char[] passKey = "123456".toCharArray();
		String algorithm;

		keyStores = KeyStore.getInstance("JCEKS");
		keyStores.load(new FileInputStream(pathToKeyStore), passKey);
		KeyStore.SecretKeyEntry ksEntry;
		if (cypherAlgorithm.equalsIgnoreCase("AES-128")) {
			ksEntry = (KeyStore.SecretKeyEntry) keyStores.getEntry("seckeyaes-128",
					new KeyStore.PasswordProtection(pass));
			algorithm = "AES/CBC/PKCS5Padding";
		} else {
			ksEntry = (KeyStore.SecretKeyEntry) keyStores.getEntry("seckeyarcfour",
					new KeyStore.PasswordProtection(pass));
			algorithm = "ARCFOUR";
		}
		SecretKey secretKey = ksEntry.getSecretKey();

		String provider = "SunJCE";
		byte cleanBlock[] = new byte[2024];
		byte cypheredBlock[];
		int blockSize;

		ByteArrayInputStream cleanDoc = new ByteArrayInputStream(doc);
		ByteArrayOutputStream cypheredDoc = new ByteArrayOutputStream();

		System.out.println("Starting doc cypher");
		Cipher cypher = Cipher.getInstance(algorithm);
		cypher.init(Cipher.ENCRYPT_MODE, secretKey);

		while ((blockSize = cleanDoc.read(cleanBlock)) > 0) {
			cypheredBlock = cypher.update(cleanBlock, 0, blockSize);
			cypheredDoc.write(cypheredBlock);
		}
		cypheredBlock = cypher.doFinal();
		cypheredDoc.write(cypheredBlock);
		System.out.println("\tCyphered alg: " + cypherAlgorithm + " Proveider: " + provider);
		cypheredDoc.close();
		cleanDoc.close();
		if (cypherAlgorithm.equals("AES-128")) {
			encoding = cypher.getParameters().getEncoded();
		}
		byte[] cypheredDocByte = cypheredDoc.toByteArray();
		return cypheredDocByte;
	}

	public byte[] getEncoding() {
		return encoding;
	}

	public byte[] DecypherDoc(byte[] chyperedDoc, byte[] encoding, String cypherAlgorithm) throws Exception {

		System.out.println("Decyphering doc");

		KeyStore keyStore;
		char[] pass = "123456".toCharArray();
		char[] passKey = "123456".toCharArray();
		String algorithm;
		String transform = "";

		keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(new FileInputStream(pathToKeyStore), passKey);
		KeyStore.SecretKeyEntry ksEntry;
		if (cypherAlgorithm.equalsIgnoreCase("AES-128")) {
			ksEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("seckeyaes-128",
					new KeyStore.PasswordProtection(pass));
			algorithm = "AES";
			transform = "/CBC/PKCS5Padding";
		} else {
			ksEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("seckeyarcfour",
					new KeyStore.PasswordProtection(pass));
			algorithm = "ARCFOUR";
		}
		SecretKey key = ksEntry.getSecretKey();

		String provider = "SunJCE";
		byte cleanBlock[];
		byte cypheredBlock[] = new byte[1024];
		int blockSize;

		Cipher decypher = Cipher.getInstance(algorithm + transform, provider);
		if (cypherAlgorithm.equals("AES-128")) {
			AlgorithmParameters params = AlgorithmParameters.getInstance(algorithm, provider);
			params.init(encoding);
			decypher.init(Cipher.DECRYPT_MODE, key, params);
		} else {
			decypher.init(Cipher.DECRYPT_MODE, key);
		}

		ByteArrayInputStream cypheredStream = new ByteArrayInputStream(chyperedDoc);
		ByteArrayOutputStream cleanStream = new ByteArrayOutputStream();

		while ((blockSize = cypheredStream.read(cypheredBlock)) > 0) {
			cleanBlock = decypher.update(cypheredBlock, 0, blockSize);
			cleanStream.write(cleanBlock);
		}
		cleanBlock = decypher.doFinal();
		System.out.println("\t Doc decyphered");
		cleanStream.write(cleanBlock);
		cypheredStream.close();
		cleanStream.close();

		return cleanStream.toByteArray();
	}

	private static void PublicKey() {

		KeyStore keyStore;
		char[] passwordKeystore = "123456".toCharArray();
		String SKCliente = "client_dsa";
		PublicKey publickey = null;
		try {
			keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(pathToTrustStore), passwordKeystore);
			publickey = keyStore.getCertificate(SKCliente).getPublicKey();
		} catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
			e.printStackTrace();
		}
		publicKey = publickey;
	}

	private PrivateKey PrivateKey() {
		KeyStore keyStore;
		char[] passwordKeystore = "123456".toCharArray();
		char[] passwordPrivateKey = "123456".toCharArray();
		String SKServidor = "serverdsa";
		PrivateKey privateKey = null;

		try {
			keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(pathToKeyStore), passwordKeystore);
			KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SKServidor,
					new KeyStore.PasswordProtection(passwordPrivateKey));
			privateKey = privateKeyEntry.getPrivateKey();
		} catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException | CertificateException
				| IOException e) {
			e.printStackTrace();
		}
		privateKeyServ = privateKey;
		return privateKey;
	}

	private static void TSAPublicKey() {

		KeyStore keyStore;
		char[] passwordKeystore = "123456".toCharArray();
		String SKCliente = "tsa_dsa";
		PublicKey publickey = null;
		try {
			keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(pathToTrustStore), passwordKeystore);
			publickey = keyStore.getCertificate(SKCliente).getPublicKey();
		} catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
			e.printStackTrace();
		}
		publicKeyTSA = publickey;
	}

	public boolean verifyTSASign(byte[] sigTSA, byte[] clientSign)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		String algorithm = "SHA1withDSA";
		int blockSize;
		byte block[] = new byte[1024];

		System.out.println("Starting TSA verify");
		ByteArrayInputStream validate = new ByteArrayInputStream(sigTSA);
		TSAPublicKey();
		// Creacion del objeto para firmar y inicializacion del objeto
		Signature verifier = Signature.getInstance(algorithm);
		return true;
		/*
		 * verifier.initVerify(publicKeyTSA); while ((longbloque =
		 * validar.read(bloque)) > 0) { verifier.update(bloque, 0, longbloque);
		 * } validar.close();
		 * 
		 * if (verifier.verify(firmacliente)) { System.out.println(
		 * "Firma del TSA correcta\n"); return true; } else {
		 * System.out.println("Firma del TSA no valida\n"); return false; }
		 */

	}

}
