
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
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

public class ClientSignVerifier {

	private static byte[] clientSign;
	private static PrivateKey privateKey;
	private static PublicKey publicKey;
	private static PublicKey publicKeyTSA;
	private static KeyStore keystore;
	private static KeyStore truststore;

	public ClientSignVerifier(KeyStore path1, KeyStore path2) {
		keystore = path1;
		truststore = path2;
	}

	public void FirmarDocumento(byte[] doc) {
		try {
			int blockSize;
			byte block[] = new byte[1024];

			PrivateKey();
			ByteArrayInputStream msg = new ByteArrayInputStream(doc);
			String algorithm = privateKey.getAlgorithm().equalsIgnoreCase("RSA") ? "MD5withRSA" : "SHA1withDSA";
			// Creacion del objeto para firmar y inicializacion del objeto
			Signature signer = Signature.getInstance(algorithm);
			signer.initSign(privateKey);
			while ((blockSize = msg.read(block)) > 0) {
				signer.update(block, 0, blockSize);
			}
			clientSign = signer.sign();
			System.out.println("Doc signed. Sign: \n\t");
			for (int i = 0; i < clientSign.length; i++)
				System.out.print(clientSign[i] + " ");
			System.out.println("\nEND\n");
			msg.close();
		} catch (Exception e) {
			System.out.println("Error signing doc:: " + e.getMessage());
		}
	}

	public byte[] getSign() {
		return clientSign;
	}

	public boolean VerifyServer(byte[] sigServC, byte[] servSign) throws Exception {

		int blockSize;
		byte block[] = new byte[1024];

		System.out.println("Verifying server: \n");
		ByteArrayInputStream validate = new ByteArrayInputStream(sigServC);
		PublicKey();
		String algorithm = publicKey.getAlgorithm().equalsIgnoreCase("RSA") ? "MD5withRSA" : "SHA1withDSA";
		// Creamos un objeto para verificar
		Signature verifier = Signature.getInstance(algorithm);

		// Inicializamos el objeto para verificar
		verifier.initVerify(publicKey);
		while ((blockSize = validate.read(block)) > 0) {
			verifier.update(block, 0, blockSize);
		}
		validate.close();
		boolean toRet = verifier.verify(servSign);
		String toPrint = toRet ? "\tValid" : "\tNot valid";
		System.out.println(toPrint);
		return toRet;
	}

	private static PrivateKey PrivateKey() throws KeyStoreException, IOException, UnrecoverableEntryException,
			NoSuchAlgorithmException, CertificateException {

		char[] passwordPrivateKey = "123456".toCharArray();
		String SKCliente = "rsa_client";

		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(SKCliente,
				new KeyStore.PasswordProtection(passwordPrivateKey));
		privateKey = privateKeyEntry.getPrivateKey();
		return privateKey;
	}

	private static void PublicKey() throws Exception {

		String SKServidor = "rsa_server_cert";
		publicKey = truststore.getCertificate(SKServidor).getPublicKey();
	}
}
