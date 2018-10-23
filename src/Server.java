import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Server {

	static KeyStore keyStore;
	static KeyStore trustStore;
	static char[] passphrase;
	static int port;
	static String cipheringAlgorithm;

	public static void main(String[] args) {

		if( getArgs(args) < 0)
			return;

		port = 5555;
		
		while(true) {

			Socket socket = waitForConection();

			int request  = getRequest();

			switch (request) {
			case 1:

				registerDocResponse();
				break;

			case 2:

				listDocsResponse();
				break;

			case 3:

				recoverDocResponse();
				break;

			default:

				System.out.println("Something went odd");
				System.out.println("Goodbye");
				return;
			}
		}
	}

	private static Socket waitForConection() {

		Socket socket;

        try {
        	
			SSLServerSocketFactory ssf = null;
			try {
				
			    SSLContext ctx;
			    KeyManagerFactory kmf;
			    TrustManagerFactory tmf;

			    ctx = SSLContext.getInstance("TLS");
			    kmf = KeyManagerFactory.getInstance("SunX509");
			    tmf = TrustManagerFactory.getInstance("SunX509");
			    
			    kmf.init(keyStore, passphrase);
			    tmf.init(trustStore);
			    ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

			    ssf = ctx.getServerSocketFactory();
			    
			} catch (Exception e) {

				e.printStackTrace();
			}    

			ServerSocket ss = ssf.createServerSocket(port);
			
			((SSLServerSocket)ss).setNeedClientAuth(true);
			
			socket = ss.accept();
		
        } catch (IOException e) {

        	e.printStackTrace();
        	return null;
		}
	
		return socket;
	}

	private static int getArgs(String[] args) {

		if(args.length != 4) {


			System.out.println("Wrong parameters");
			System.out.println("Server keyStoreFile KeyStorePassword trustStoreFile cipheringAlgorithm");
			return -1;

		} else {

			try {
				
				String keyStoreName = args[0];
				String keyStorePassword = args[1];

				passphrase = keyStorePassword.toCharArray();

				keyStore = KeyStore.getInstance("JKCE");
				keyStore.load(new FileInputStream(keyStoreName), passphrase);

				String trustStoreName = args[2];

				trustStore = KeyStore.getInstance("JKCE");
				trustStore.load(new FileInputStream(trustStoreName),passphrase);

				cipheringAlgorithm = args[3];

			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
				// TODO Auto-generated catch block

				e.printStackTrace();
				return -1;
			}

			return 1;
		}
	}

}
