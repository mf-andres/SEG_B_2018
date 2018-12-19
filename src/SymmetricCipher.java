import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.*;
import javax.crypto.spec.*;

public class SymmetricCipher {
	public static byte[] cifrado(byte[] archivoClaro, KeyStore serverKeystore, String passKeyStore,
			String SecretKeyEntryAlias)
			throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
			NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {

		ByteArrayInputStream ftextoclaro = new ByteArrayInputStream(archivoClaro);
		ByteArrayOutputStream ftextocifrado = new ByteArrayOutputStream();
		FileOutputStream parametrosCifrado = new FileOutputStream("parametrosCifrado");

		byte bloqueclaro[] = new byte[2024];
		byte bloquecifrado[] = new byte[2048];
		String algoritmo = "AES";
		String transformacion = "/CBC/PKCS5Padding";
		int longclave = 128;
		int longbloque;

		// ************** LEER LA CLAVE SECRETA **************************	
		
		SecretKeySpec kreg = Claves.getClaveSecreta(passKeyStore, serverKeystore, SecretKeyEntryAlias, algoritmo);

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

		// obtencion de los paramentros del cifrado, es necesario para poder descifrar
		// en bloque
		byte[] parametros = cifrador.getParameters().getEncoded();
		parametrosCifrado.write(parametros);

		// Cerrar ficheros
		ftextocifrado.close();
		ftextoclaro.close();
		parametrosCifrado.close();

		System.out.println("Fin Cifrado");
		return ftextocifrado.toByteArray();
	}

	public static byte[] descifrado(byte[] archivoCifrado, KeyStore serverKeystore, String passKeyStore,
			String SecretKeyEntryAlias) throws InvalidKeyException, NoSuchAlgorithmException,
			UnrecoverableEntryException, KeyStoreException, NoSuchPaddingException, IOException,
			IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, NoSuchProviderException,
			InvalidAlgorithmParameterException, CertificateException {
		String algoritmo = "AES";
		String transformacion = "/CBC/PKCS5Padding";
		int longbloque;
		String provider = "SunJCE";

		ByteArrayInputStream ftextocifrado2 = new ByteArrayInputStream(archivoCifrado);
		ByteArrayOutputStream ftextoclaro2 = new ByteArrayOutputStream();
		FileInputStream fparametros_in = new FileInputStream("parametrosCifrado");

		byte bloquecifrado2[] = new byte[1024];
		byte bloqueclaro2[] = new byte[1048];

		System.out.println("*************** INICIO DESCIFRADO *****************");

		char[] key_password = passKeyStore.toCharArray();

		KeyStore.SecretKeyEntry pkEntry = (KeyStore.SecretKeyEntry) serverKeystore.getEntry(SecretKeyEntryAlias,
				new KeyStore.PasswordProtection(key_password));

		byte[] kreg_raw = pkEntry.getSecretKey().getEncoded();
		SecretKeySpec kreg = new SecretKeySpec(kreg_raw, algoritmo);

		Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);

		AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo, provider);
		byte[] paramSerializados = new byte[fparametros_in.available()];

		fparametros_in.read(paramSerializados);
		params.init(paramSerializados);

		System.out.println("Parametros del descifrado ... = " + params.toString());

		descifrador.init(Cipher.DECRYPT_MODE, kreg, params);

		while ((longbloque = ftextocifrado2.read(bloquecifrado2)) > 0) {

			bloqueclaro2 = descifrador.update(bloquecifrado2, 0, longbloque);
			ftextoclaro2.write(bloqueclaro2);
		}

		bloqueclaro2 = descifrador.doFinal();
		ftextoclaro2.write(bloqueclaro2);

		ftextocifrado2.close();
		ftextoclaro2.close();
		fparametros_in.close();
		System.out.println("*************** FIN DESCIFRADO *****************");
		return ftextoclaro2.toByteArray();
	}

}
