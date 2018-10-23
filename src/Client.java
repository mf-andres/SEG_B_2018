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
	Scanner in;

	public static void main(String[] args) {

		say("Getting arguments");
		if( getArgs(args) < 0)
			return;

		say("Setting net parameters");
		try {

			host = InetAddress.getLocalHost();

		} catch (UnknownHostException e1) {

			e1.printStackTrace();
			return;
		}

		port = 5555;

		say("Getting the suite");
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

				say("Exiting");
				say("Goodbye");
				return;

			default:

				say("Wrong action");
				break;
			}
		}
	}

	private static void say(String string) {
		
		System.out.println(string);
	}
	
	private static String getSuite() throws NoSuchAlgorithmException {

		String selectedSuite;

		SSLContext ctx = SSLContext.getDefault();
		SSLSocketFactory factory = ctx.getSocketFactory();
		String[] suites = factory.getSupportedCipherSuites();

		say("Supported suites:");
		for(int i = 0; i < suites.length; i++) {

			String suite = suites[i];
			say(i + ") " + suite);
		}

		Scanner in = new Scanner(System.in);

		int suiteNumber = in.nextInt();
		selectedSuite = suites[suiteNumber];

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

			keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(keyStoreName), passphrase);

			trustStore = KeyStore.getInstance("JCEKS");
			trustStore.load(new FileInputStream(trustStoreName), passphrase);

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
		
			e.printStackTrace();
		}
	}

	private static void setPassphrase() {

		say("Insert KeyStore password:");

		Scanner in = new Scanner(System.in);

		passphrase = in.nextLine().toCharArray();
		
		say("Thank you");

		in.close();
	}

	private static int getAction() {

		int action = 4;

		say("Select action:");
		say("1) Register document");
		say("2) List documents");
		say("3) Recover document");
		say("4) Exit");

		Scanner in = new Scanner(System.in);

		action = in.nextInt();

		say("Thank you");
		
		in.close();

		return action;
	}

	private static int getArgs(String[] args) {

		if(args.length != 2) {

			say("Wrong parameters!");
			say("Client keyStoreFile trustStoreFile");

			return -1;
			
		} else {

			keyStoreName = args[0];
			trustStoreName = args[1];

			return 1;
		}
	}

}
