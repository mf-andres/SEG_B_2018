
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricCipher {
	public static byte[] cifrado(byte[] archivoClaro, KeyStore keyStore, String passKeyStore, String SecretKeyEntryAlias) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, KeyStoreException {
		
		ByteArrayInputStream ftextoclaro = new ByteArrayInputStream(archivoClaro);
		ByteArrayOutputStream 	ftextocifrado 	= new ByteArrayOutputStream();
		String provider = "SunJCE";
		String algoritmo 		= "RSA";
		String transformacion1 	= "/ECB/PKCS1Padding"; //Relleno de longitud fija de 88 bits (11 bytes)
		int longclave 			= 1024;               // NOTA -- Probar a subir este valor e ir viendo como 
		                                              //         disminuye significativamente la velocidad de descifrado 
		int longbloque;
		long t, tbi, tbf; 	    // tiempos totales y por bucle
		double lf; 				// longitud del fichero

		byte bloqueclaro[] 		= new byte[(longclave/8) - 11]; // *** NOTA: Calculo solo valido para relleno PKCS1Padding ****
		byte bloquecifrado[] 	= new byte[2048];
		
		/************************************************************
		 * LEER CLAVE PUBLICA
		 ************************************************************/
		PublicKey publicKey = Claves.getClavePublica(keyStore, SecretKeyEntryAlias);
		
		/************************************************************
		 * CIFRAR
		 ************************************************************/
		System.out.println("*** INICIO CIFRADO " + algoritmo + "-" + longclave
				+ " ************");

		Cipher cifrador = Cipher.getInstance(algoritmo + 
				                             transformacion1);
		cifrador.init(Cipher.ENCRYPT_MODE, publicKey);
		// Datos para medidas de velocidad cifrado
		t = 0; lf = 0; tbi = 0;  tbf = 0;

		while ((longbloque = ftextoclaro.read(bloqueclaro)) > 0) {

			lf = lf + longbloque;

			tbi = System.nanoTime();
			
			bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
			bloquecifrado = cifrador.doFinal();

			tbf = System.nanoTime();
			t = t + tbf - tbi;

			ftextocifrado.write(bloquecifrado);
		}
		
		// Escribir resultados velocidad cifrado

		System.out.println("*** FIN CIFRADO " + algoritmo + "-" + longclave
											  + " Provider: " + provider);
		System.out.println("Bytes  cifrados = " + (int) lf);
		System.out.println("Tiempo cifrado  = " + t / 1000000 + " mseg");
		System.out.println("Velocidad       = " + (lf * 8 * 1000) / t + " Mpbs");

		// Cerrar ficheros
		ftextocifrado.close();
		ftextoclaro.close();
		
		return ftextocifrado.toByteArray();
	}
	
	
	
	public static byte[] descifrado(byte[] archivoCifrado, KeyStore keyStore, String passKeyStore,
			String SecretKeyEntryAlias) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, KeyStoreException, UnrecoverableEntryException  {
		String provider = "SunJCE";
		String algoritmo = "RSA";
		String transformacion1 = "/ECB/PKCS1Padding"; // Relleno de longitud fija de 88 bits (11 bytes)
		int longclave = 1024; // NOTA -- Probar a subir este valor e ir viendo como
		int longbloque;
		
		/************************************************************
		 * LEER CLAVE
		 ************************************************************/
		
		PrivateKey privateKey = Claves.getClavePrivada(keyStore, SecretKeyEntryAlias, passKeyStore);
		
		// *****************************************************************************
		// DESCIFRAR
		// *****************************************************************************
		ByteArrayInputStream ftextocifrado2 = new ByteArrayInputStream(archivoCifrado);
		ByteArrayOutputStream ftextoclaro2 = new ByteArrayOutputStream();

		byte bloquecifrado2[] = new byte[longclave / 8];
		byte bloqueclaro2[] = new byte[512]; // *** Buffer sobredimensionado ***

		System.out.println("\n*** INICIO DESCIFRADO " + algoritmo + "-" + longclave + " ************");

		Cipher descifrador = Cipher.getInstance(algoritmo + transformacion1, provider);

		descifrador.init(Cipher.DECRYPT_MODE, privateKey);

		// Datos para medidas de velocidad descifrado
		while ((longbloque = ftextocifrado2.read(bloquecifrado2)) > 0) {
			bloqueclaro2 = descifrador.update(bloquecifrado2, 0, longbloque);
			bloqueclaro2 = descifrador.doFinal();
			ftextoclaro2.write(bloqueclaro2);
		}

		ftextocifrado2.close();
		ftextoclaro2.close();

		System.out.println("*** FIN DESCIFRADO " + algoritmo + "-" + longclave + " Provider: " + provider);
	
		return ftextoclaro2.toByteArray();
	}

	
	

}
