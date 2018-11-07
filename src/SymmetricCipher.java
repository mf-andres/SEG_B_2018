import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SymmetricCipher {
	public static void cifrado(String archivoClaro, KeyStore serverKeystore, String passKeyStore, String SecretKeyEntryAlias)
			throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
			NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {

		// FileOutputStream fclave = new FileOutputStream(serverKeystore);
		// FileInputStream fclave_in = new FileInputStream (ARCHIVO_KEYSTORE_CIFRADO);
		FileInputStream ftextoclaro = new FileInputStream(archivoClaro);
		FileOutputStream ftextocifrado = new FileOutputStream(archivoClaro+"_cifrado");

		byte bloqueclaro[] = new byte[2024];
		byte bloquecifrado[] = new byte[2048];
		String algoritmo = "AES";
		String transformacion = "/CBC/PKCS5Padding";
		int longclave = 128;
		int longbloque;

		// ************** LEER LA CLAVE SECRETA **************************

		char[] key_password = passKeyStore.toCharArray();

		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) serverKeystore.getEntry(SecretKeyEntryAlias,
				new KeyStore.PasswordProtection(key_password));

		byte[] kreg_raw = pkEntry.getSecretKey().getEncoded();
		SecretKeySpec kreg = new SecretKeySpec(kreg_raw, algoritmo);

		System.out.println("*** INICIO CIFRADO " + algoritmo + "-" + longclave + " ************");

		Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);

		// Se cifra con la modalidad opaca de la clave

		cifrador.init(Cipher.ENCRYPT_MODE, kreg);

		while ((longbloque = ftextoclaro.read(bloqueclaro)) > 0) {
			bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
			ftextocifrado.write(bloquecifrado);
		}

		bloquecifrado = cifrador.doFinal();
		ftextocifrado.write(bloquecifrado);

		// Cerrar ficheros
		ftextocifrado.close();
		ftextoclaro.close();
		

	}

	public static void descifrado(String archivoCifrado, KeyStore serverKeystore, String passKeyStore, String SecretKeyEntryAlias)
			throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
			NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {

		
		//esta pegado tal cual el cifrado
		
		FileInputStream ftextoclaro = new FileInputStream(archivoCifrado);
		FileOutputStream ftextocifrado = new FileOutputStream(archivoCifrado+"_descifrado");

		byte bloqueclaro[] = new byte[2024];
		byte bloquecifrado[] = new byte[2048];
		String algoritmo = "AES";
		String transformacion = "/CBC/PKCS5Padding";
		int longclave = 128;
		int longbloque;

		// ************** LEER LA CLAVE SECRETA **************************

		char[] key_password = passKeyStore.toCharArray();

		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) serverKeystore.getEntry(SecretKeyEntryAlias,
				new KeyStore.PasswordProtection(key_password));

		byte[] kreg_raw = pkEntry.getSecretKey().getEncoded();
		SecretKeySpec kreg = new SecretKeySpec(kreg_raw, algoritmo);
		
		
		// *** parametros 

		System.out.println("*** INICIO CIFRADO " + algoritmo + "-" + longclave + " ************");

		Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);

		// Se cifra con la modalidad opaca de la clave

		cifrador.init(Cipher.ENCRYPT_MODE, kreg);

		while ((longbloque = ftextoclaro.read(bloqueclaro)) > 0) {
			bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
			ftextocifrado.write(bloquecifrado);
		}

		bloquecifrado = cifrador.doFinal();
		ftextocifrado.write(bloquecifrado);

		// Cerrar ficheros
		ftextocifrado.close();
		ftextoclaro.close();
		

	}

}
