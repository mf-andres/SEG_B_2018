import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Scanner;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Client {

	static String keyStoreName;
	static KeyStore keyStore;
	static String trustStoreName;
	static KeyStore trustStore;
	static char[] passphrase;
	static InetAddress host;
	static int port;
	static String suite;

	public static void main(String[] args) {

		if( getArgs(args) < 0)
			return;

		try {

			host = InetAddress.getLocalHost();

		} catch (UnknownHostException e1) {

			e1.printStackTrace();
			return;
		}

		port = 5555;

		try {

			suite = getSuite();

		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
			return;
		}

		while(true) {

			int action = getAction();

			switch (action) {
			case 1:

				Object o = registerDoc();
				if(o == null) {

					return;
				}
				break;

			case 2:

				Object o1 = listDocs();
				if(o1 == null) {

					return;
				}
				break;
				
			case 3:

				Object o2 = recoverDoc();
				if(o2 == null) {

					return;
				}
				break;

			case 4:

				System.out.println("Exiting");
				System.out.println("Goodbye");
				return;

			default:

				System.out.println("Wrong action");
				break;
			}
		}
	}

	private static String getSuite() throws NoSuchAlgorithmException {

		String selectedSuite;

		SSLContext ctx = SSLContext.getInstance("TLS");
		SSLSocketFactory factory = ctx.getSocketFactory();
		String[] suites = factory.getSupportedCipherSuites();

		System.out.println("Supported suites:");
		for(int i = 0; i < suites.length; i++) {

			String suite = suites[i];
			System.out.print(i + ") " + suite);
		}

		Scanner in = new Scanner(System.in);

		selectedSuite = suites[in.nextInt()];

		in.close();

		return selectedSuite;
	}

	private static Object recoverDoc() {

		setPassphrase();
		setKeyStoreAndTruStore();
		Socket socket = setConnection();

		if(socket == null)
			return null;
		
		try {
			
			socket.close();
			
		} catch (IOException e) {
			
			e.printStackTrace();
			return null;
		}
		
		return null;
	}

	private static Object listDocs() {

		setPassphrase();
		setKeyStoreAndTruStore();
		Socket socket = setConnection();

		if(socket == null)
			return null;
		
		try {
			
			socket.close();
			
		} catch (IOException e) {
			
			e.printStackTrace();
			return null;
		}
		
		return null;
	}

	private static Object registerDoc() {

		setPassphrase();
		setKeyStoreAndTruStore();
		Socket socket = setConnection();

		if(socket == null)
			return null;

		try {
			
			socket.close();
			
		} catch (IOException e) {
			
			e.printStackTrace();
			return null;
		}
		
		return null;
	}

	private static Socket setConnection() {

		SSLSocket socket;

		try {

			SSLSocketFactory factory = null;
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

				factory = ctx.getSocketFactory();

			} catch (Exception e) {

				throw new IOException(e.getMessage());
			}

			socket = (SSLSocket)factory.createSocket(host, port);

			String[] suiteArray = {suite};
			socket.setEnabledCipherSuites(suiteArray);

			socket.startHandshake();

		} catch (IOException e) {

			e.printStackTrace();
			return null;
		}

		return socket;
	}

	private static void setKeyStoreAndTruStore() {

		try {

			keyStore = KeyStore.getInstance("JKCE");
			keyStore.load(new FileInputStream(keyStoreName), passphrase);

			trustStore = KeyStore.getInstance("JKCE");
			trustStore.load(new FileInputStream(trustStoreName), passphrase);

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static void setPassphrase() {

		System.out.println("Insert KeyStore password:");

		Scanner in = new Scanner(System.in);

		passphrase = in.nextLine().toCharArray();

		in.close();
	}

	private static int getAction() {

		int action = 4;

		System.out.println("Select action:");
		System.out.println("1) Register document");
		System.out.println("2) List documents");
		System.out.println("3) Recover document");
		System.out.println("4) Exit");

		Scanner in = new Scanner(System.in);

		action = in.nextInt();

		in.close();

		return action;
	}

	private static int getArgs(String[] args) {

		if(args.length != 2) {

			System.out.println("Wrong parameters!");
			System.out.println("Client keyStoreFile trustStoreFile");

			return -1;
		} else {

			keyStoreName = args[0];
			trustStoreName = args[1];

			return 1;
		}
	}

}
