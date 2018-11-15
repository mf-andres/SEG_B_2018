import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricCipher {
	public static void cifrado(String archivoClaro, KeyStore keyStore, String passKeyStore,
			String SecretKeyEntryAlias)
			throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
			NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException {

		FileInputStream ftextoclaro = new FileInputStream(archivoClaro);
		FileOutputStream ftextocifrado = new FileOutputStream("c_" + archivoClaro);
		FileOutputStream parametrosCifrado = new FileOutputStream("parametrosCifrado");

		byte bloqueclaro[] = new byte[2024];
		byte bloquecifrado[] = new byte[2048];
		String algoritmo = "AES";
		String transformacion = "/CBC/PKCS5Padding";
		int longclave = 128;
		int longbloque;

		// ************** LEER LA CLAVE PUBLICA DEL DESCIFRADOR **************************
		PublicKey  publicKeyDescifrador = Claves.getClavePublica(keyStore, SecretKeyEntryAlias);

		System.out.println("*** INICIO CIFRADO " + algoritmo + "-" + longclave + " ************");

		Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);

		// Se cifra con la modalidad opaca de la clave

		cifrador.init(Cipher.ENCRYPT_MODE, publicKeyDescifrador);

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
	}
	
	
	public static void descifrado(String archivoCifrado, KeyStore keyStore, String passKeyStore,
			String SecretKeyEntryAlias) throws InvalidKeyException, NoSuchAlgorithmException,
			UnrecoverableEntryException, KeyStoreException, NoSuchPaddingException, IOException,
			IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, NoSuchProviderException,
			InvalidAlgorithmParameterException, CertificateException {
		String algoritmo = "AES";
		String transformacion = "/CBC/PKCS5Padding";
		int longbloque;
		String provider = "SunJCE";

		FileInputStream ftextocifrado2 = new FileInputStream(archivoCifrado);
		FileOutputStream ftextoclaro2 = new FileOutputStream("d_" + archivoCifrado);
		FileInputStream fparametros_in = new FileInputStream("parametrosCifrado");

		byte bloquecifrado2[] = new byte[1024];
		byte bloqueclaro2[] = new byte[1048];

		System.out.println("*************** INICIO DESCIFRADO *****************");
		
		// obtengo mi clave privada
		PrivateKey kreg = Claves.getClavePrivada(keyStore, SecretKeyEntryAlias, passKeyStore);
		

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
	}
	
}
