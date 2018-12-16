package tsa;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.sql.Timestamp;

import messages.TimestampRequest;
import messages.TimestampResponse;

public class TSAConnection extends Thread {

	private static byte[] firma;

	public byte[] firmarSelloTemporal(byte[] firmaTSA) {

		try {
			String algoritmo = "SHA1withDSA";
			int longbloque;
			byte bloque[] = new byte[1024];

			PrivateKey privateKey = ClavePrivada();
			ByteArrayInputStream mensaje = new ByteArrayInputStream(firmaTSA);

			Signature signer = Signature.getInstance(algoritmo);
			signer.initSign(privateKey);
			while ((longbloque = mensaje.read(bloque)) > 0) {
				signer.update(bloque, 0, longbloque);
			}
			firma = signer.sign();
			System.out.println("Documento firmado. Firma: ");
			for (int i = 0; i < firma.length; i++) {
				System.out.print(firma[i] + " ");
			}
			System.out.println("\n---- Fin de la firma ----\n");
			mensaje.close();

		} catch (InvalidKeyException | SignatureException | IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return firma;
	}

	private PrivateKey ClavePrivada() {
		KeyStore keyStore;
		char[] passwordKeystore = "password".toCharArray();
		char[] passwordPrivateKey = "password".toCharArray();
		String pathkeystore = "keyStoreTSAPath";
		String SKServidor = "tsa_dsa2";
		PrivateKey privateKey = null;

		try {
			keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(pathkeystore), passwordKeystore);
			KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SKServidor,
					new KeyStore.PasswordProtection(passwordPrivateKey));
			privateKey = privateKeyEntry.getPrivateKey();
		} catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException | CertificateException
				| IOException e) {
			e.printStackTrace();
		}
		return privateKey;
	}
}
