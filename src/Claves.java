import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;

import javax.crypto.spec.SecretKeySpec;

public class Claves {
	public static SecretKeySpec getClaveSecreta(String passKeyStore, KeyStore keyStore, String SecretKeyEntryAlias,
			String algoritmo) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException {
		char[] key_password = passKeyStore.toCharArray();

		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(SecretKeyEntryAlias,
				new KeyStore.PasswordProtection(key_password));

		byte[] kreg_raw = pkEntry.getSecretKey().getEncoded();
		SecretKeySpec kreg = new SecretKeySpec(kreg_raw, algoritmo);
		return kreg;
	}

	public static PrivateKey getClavePrivada(KeyStore keyStore, String SecretKeyEntryAlias,String passKeyStore ) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException {
		System.out.println("La contraseña es: "+passKeyStore);
		passKeyStore="123456";
		char[] key_password = passKeyStore.toCharArray();
		KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SecretKeyEntryAlias,
				new KeyStore.PasswordProtection(key_password));
		PrivateKey privateKey = pkEntry.getPrivateKey();
		return privateKey;
	}

	public static PublicKey getClavePublica(KeyStore keyStore, String SecretKeyEntryAlias) throws KeyStoreException {
		// Obtener la clave publica del keystore
		PublicKey publicKey = keyStore.getCertificate(SecretKeyEntryAlias).getPublicKey();
		return publicKey;
	}

}
