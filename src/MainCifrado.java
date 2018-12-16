import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainCifrado {

	public static void main(String[] args) throws NoSuchAlgorithmException, CertificateException, InvalidKeyException,
			UnrecoverableEntryException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, NoSuchProviderException, InvalidAlgorithmParameterException {

		// cifrado
		try {

			/* SIMETRICO OK
			final String archivoClaro = "tux.png";
			final String passKeyStore = "123456";
			final String SecretKeyEntryAlias = "serverrsa";
			final String archivoKeyStore = "ServerKeyStore.jce";
			
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(archivoKeyStore), passKeyStore.toCharArray());
			SymmetricCipher.cifrado(archivoClaro, keyStore, passKeyStore, SecretKeyEntryAlias);
			*/
			
			///* ASIMETRICO
			
			final String archivoClaro = "tux.png";
			final String passKeyStore = "123456";

			final String SecretKeyEntryAlias = "rsa_server_cert";
			final String archivoKeyStore = "ClientTrustStore.jce";

			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(archivoKeyStore), passKeyStore.toCharArray());
			AsymmetricCipher.cifrado(archivoClaro, keyStore, passKeyStore, SecretKeyEntryAlias);
			//*/
			
		} catch (KeyStoreException | IOException e) {
			System.out.println("Se produjo un error al cargar el KeyStore: " + e.getMessage());
			e.printStackTrace();
			return;
		}

		System.out.println("fin_cifrado");

// descifrado
		try {
			///* ASIMETRICO
			
			final String archivoClaro = "tux.png";
			final String passKeyStore = "123456";
			
			final String SecretKeyEntryAlias = "rsa_server";
			final String archivoKeyStore = "ServerKeyStore.jce";


			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(archivoKeyStore), passKeyStore.toCharArray());

			AsymmetricCipher.descifrado("cifrado", keyStore, passKeyStore, SecretKeyEntryAlias);

		} catch (KeyStoreException | IOException e) {
			System.out.println("Se produjo un error al cargar el KeyStore descifrado: " + e.getMessage());
			e.printStackTrace();
			return;
		}
		System.out.println("fin descifrado");
	}

}
