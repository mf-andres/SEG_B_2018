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
import java.util.TreeMap;

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
	static TreeMap<Integer, byte[]> hashedDocsTree; //arbol que almacena valores hash de los documentos registrados junto a su número de registro

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
		
		byte[] myAuthCert = getMyAuthCert();
		
		int RID = getRID();
	
		Object response = sendRecDocReq(myAuthCert, RID);
		
		if(response instanceof String) {
			
			say((String)response);
			
		} else {
		
			// TODO duda: si siempre codificamos la comunicación no tiene por qué devolverse confType
			//String confType = ((Response) response).getConfType();
			// TODO duda : la especificación indica que se devolverá el RID pero ya debería ser el que le pasamos nosotros
			// opto por trabajar con el que le pasamos nosotros
			//int respRID = ((Response) response).getRID();
			String timeStamp = ((Response) response).getTimeStamp();
			byte[] cypheredDoc = ((Response) response).getCypheredDoc();
			byte[] serverSignature = ((Response) response).getServerSignature();
			byte[] serverSignCert = ((Response) response).getServerSignedCert();
			
			if( ! validateServerSignCert(serverSignCert) ){
				
				say("CERTIFICADO DE REGISTRADOR INCORRECTO");
				
			} else {
				
				byte[] myPrivateKey = getMyPrivateKey();
				byte[] documentBytes = decypherDoc(cypheredDoc, myPrivateKey);

				// TODO duda: en principio siempre ciframos en comunicación, pero en este punto el documento no es claro
				// propongo optar por cifrar siempre
				
				// TODO duda: aquí hay que ver si se puede usar la misma función para ambas funciones
				if( ! verifyServerSign(serverSignature, documentBytes, null)) {
					
					say("FALLO DE FIRMA DEL REGISTRADOR");
					
				} else {
					
					byte[] hashedDoc = hashDoc(documentBytes);
					byte[] OriginalHashedDoc = hashedDocsTree.get(RID);
					
					if( ! hashedDoc.equals(OriginalHashedDoc) ) {
						
						say("DOCUMENTO ALTERADO POR EL REGISTRADOR");
					
					} else {
						
						say("DOCUMENTO RECUPERADO CORRECTAMENTE " + RID + " " + timeStamp );
						archiveDoc(documentBytes);
					}
				}
			}
		}
		
		return null;
	}

	//stores the recovered document in the user's file system
	private static void archiveDoc(byte[] documentBytes) {
		
	}

	private static byte[] decypherDoc(byte[] cypheredDoc, byte[] myPrivateKey) {
		return null;
	}

	//ask the user about the register identifier of the document it wants to recover 
	private static int getRID() {
		return 0;
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
		
		String confType = getConfTyep();
		
		byte[] myAuthCert = getMyAuthCert();

		// TODO aquí la forma de imprimir la respuesta quizá no sea la más indicada
		String response = sendListDocReq(confType, myAuthCert);
		
		say(response);
		
		return null;
	}

	private static byte[] getMyAuthCert() {
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
		
		Document document = getDocument();

		String docName = document.getName();
		
		byte[] documentBytes = document.getBytes();
		
		String confType = getConfTyep();
		
		byte[] serverPublicKey = getServerPublicKey();
		
		byte[] myPrivateKey = getMyPrivateKey();
		
		byte[] cypheredDoc = cypherDoc(documentBytes, serverPublicKey);
		
		byte[] signedDoc = signDoc(cypheredDoc, myPrivateKey);

		byte[] mySignCert = getMySignCert();
		
		Object response = sendRegDocReq(docName, confType, cypheredDoc, signedDoc, mySignCert);
		
		if(response instanceof String) {
			
			say((String)response);

		} else {
			
			int RID = ((Response) response).getRID();
			String timeStamp = ((Response)response).getTimeStamp();
			byte[] serverSignature = ((Response)response).getServerSignature();
			byte[] serverSignCert = ((Response)response).getServerSignCert();
			
			if( ! validateServerSignCert(serverSignCert) ) {
				
				
				say("CERTIFICADO DE REGISTRADOR INCORRECTO");
				
			} else {
				
				if( ! verifyServerSign(serverSignature, documentBytes, signedDoc) ) {
					
					say("FIRMA INCORRECTA DEL REGISTRADOR");
					
				} else {
					
					say("Documento correctamente registrado con el numero " + RID + " " + timeStamp);
					
					byte[] hashedDoc = hashDoc(documentBytes);
					
					hashedDocsTree.put(RID, hashedDoc);
					
//					//este método se supone que borra del equipo ambas cosas, pero si no las guardamos en el eqipo qué?
//					deleteDocAndSignature();
				}
			}
		}
		
		
		
		return null;
	}

	//hash the document and store it in the hashedDocsTree
	private static byte[] hashDoc(byte[] documentBytes) {
		
		return null;
	}

	//TODO esta función es probable que esté mal definida. Hay que tener en cuenta la respuesta del servidor a recgiste doc
	//hay que estudiarlo
	private static boolean verifyServerSign(byte[] serverSignature, byte[] documentBytes, byte[] signedDoc) {
		return false;
		
	}

	private static boolean validateServerSignCert(byte[] serverSignCert) {
		return false;
		
	}

	//ask the client about the type of confidentiality it wants
	private static String getConfTyep() {
		return null;
	}

	//ask the client about what document it wants to send and obtain it
	private static Document getDocument() {
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

	//to later cipher if typeConf is private
	private static byte[] getServerPublicKey(){
		return null;
		
	}
	
	//to sign the doc
	private static byte[] getMyPrivateKey() {
		return null;
		
	}
	
	//asymmetrically, with the server public key, to send the doc
	private static byte[] cypherDoc(byte[] documentBytes, byte[] serverPublicKey) {
	
		return null;
	}
	
	//with my private key, over the ciphered doc
	private static byte[] signDoc(byte[] cypheredDoc, byte[] myPrivateKey) {
		
		return null;
	}
	
	//to obtain the public key certificate for signing in order to send it to the server
	private static byte[] getMySignCert() {
		
		return null;
	}
	
	private static String sendRegDocReq(String docName, String confType, byte[] cypheredDoc, byte[] signedDoc, byte[] mySignCert){
		
		return null;
	}
	
	private static String sendListDocReq(String confType, byte[] myAuthCert){
		
		return null;
	}
	
	private static String sendRecDocReq(byte[] myAuthCert, int rID){
		
		return null;
	}

	
}
