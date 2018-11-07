import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainCifrado {

	public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException, InvalidKeyException,
			UnrecoverableEntryException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		final String archivoClaro = "tux.png";
		final String passKeyStore = "123456";
		final String SecretKeyEntryAlias = "serverauthcert";
		final String archivoKeyStore = "ServerKeyStore.jce";

		// cifrado
		try {

			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(archivoKeyStore), passKeyStore.toCharArray());

			SymmetricCipher.cifrado(archivoClaro, keyStore, passKeyStore, SecretKeyEntryAlias);

		} catch (KeyStoreException | IOException e) {
			System.out.println("Se produjo un error al cargar el KeyStore: " + e.getMessage());
			e.printStackTrace();
			return;
		}
		
		

	}

}
