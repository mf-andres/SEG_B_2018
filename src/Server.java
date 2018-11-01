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

		say("Getting arguments");
		if( getArgs(args) < 0)
			return;

		say("Setting net parameters");
		port = 5555;
		
		say("Entering infinite loop");
		while(true) {

			say("Waiting for conection");
			Socket socket = waitForConection();

			say("Waiting for request");
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

				say("Something went odd");
				say("Goodbye");
				return;
			}
		}
	}

	private static void say(String string) {
		
		System.out.println(string);
	}

	private static int getRequest() {
		return 0;
	}

	private static void recoverDocResponse() {
		// TODO Auto-generated method stub
		
	}

	private static void listDocsResponse() {
		// TODO Auto-generated method stub
		
	}

	private static void registerDocResponse() {
		// TODO Auto-generated method stub
		
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
		
			say("Conection acepted");
			
        } catch (IOException e) {

        	e.printStackTrace();
        	return null;
		}
	
		return socket;
	}

	private static int getArgs(String[] args) {

		if(args.length != 4) {


			say("Wrong parameters");
			say("Server keyStoreFile KeyStorePassword trustStoreFile cipheringAlgorithm");
			return -1;

		} else {

			try {
				
				String keyStoreName = args[0];
				String keyStorePassword = args[1];

				passphrase = keyStorePassword.toCharArray();

				keyStore = KeyStore.getInstance("JCEKS");
				keyStore.load(new FileInputStream(keyStoreName), passphrase);

				String trustStoreName = args[2];

				trustStore = KeyStore.getInstance("JCEKS");
				trustStore.load(new FileInputStream(trustStoreName),passphrase);

				cipheringAlgorithm = args[3];

			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {

				e.printStackTrace();
				return -1;
			}

			return 1;
		}
	}

	void validateClientSignCert() {
		
	}

	void verifyDoc() {
		
	}
	
	void decipherDoc() {
		
	}
	
	//get an int that identifies the document
	void getRID(){
		
	}
	
	//get a string that specifies the moment the document was stored
	void getTimestamp() {
		
	}
	
	//symmetric ciphering with secret key
	void cipherDocForStorage() {
		
	}
	
	void decipherDocForStorage() {
		
	}
	
	void storeDoc() {
		
	}
	
	//tells whether or not a document is stored
	void docExists() {
		
	}
	
	//tells whether the user has permit to access the document and whether the document is private or public
	void userHasPermit() {
		
	}
	
	//elaborate register document response
	void sendRegDocRes(){
		
	}
	
	//elaborate list documents response
	void sendListDocRes() {
		
	}
	
	//elaborate recover document response
	void sendRecDocRes() {
		
	}
	
	//recover a list of the publicly stored documents
	void getPublicDocs() {
		
	}
	
	//recover a list of the privatly stored documents
	void getPrivateDocs() {
		
	}
	
	//recover a given stored doc
	void getDoc() {
		
	}
	
	//obtains the client public key
	void getClientPublicKey() {
		
	}
	
	//asymetrically with the clients key, to cipher and send the doc
	void cipherDoc() {
		
	}
	
	
}

