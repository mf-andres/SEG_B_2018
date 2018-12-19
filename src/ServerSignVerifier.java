
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
	private static KeyStore keystore;
	private static KeyStore truststore;

	public ServerSignVerifier(KeyStore path1, KeyStore path2) {
		keystore = path1;
		truststore = path2;
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


	private static void PublicKey() {

		String SKCliente = "rsa_client_cert";
		PublicKey publickey = null;
		try {
			publickey = truststore.getCertificate(SKCliente).getPublicKey();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		publicKey = publickey;
	}

	private PrivateKey PrivateKey() {
		
		char[] passwordPrivateKey = "123456".toCharArray();
		String SKServidor = "rsa_server";
		PrivateKey privateKey = null;

		try {
			KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(SKServidor,
					new KeyStore.PasswordProtection(passwordPrivateKey));
			privateKey = privateKeyEntry.getPrivateKey();
		} catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		privateKeyServ = privateKey;
		return privateKey;
	}
}
