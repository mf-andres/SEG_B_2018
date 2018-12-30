import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Scanner;
import java.util.TreeMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
	static Scanner in = new Scanner(System.in);;
	static TreeMap<Integer, byte[]> hashedDocsTree = new TreeMap<Integer, byte[]>(); //arbol que almacena valores hash de los documentos registrados junto a su n√∫mero de registro

	public static void main(String[] args) {

		say("Getting arguments");
		if( getArgs(args) < 0) {		
			return;
		}

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

				say("Register document");
				try {
					registerDoc();
				} catch (IOException | ClassNotFoundException e) {
					e.printStackTrace();
				}
				break;

			case 2:

				say("List documents");
				try {
					listDocs();
				} catch (IOException | ClassNotFoundException e) {
					e.printStackTrace();
				}
				break;

			case 3:

				say("Recover document");
				try {
					recoverDoc();
				} catch (IOException | ClassNotFoundException e) {
					e.printStackTrace();
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

	//stores the recovered document in the user's file system
	private static void storeDoc(byte[] hashedDoc, byte[] documentBytes) {
		
		Path path = Paths.get("doc_" + hashedDoc);
		try {
			Files.write(path, documentBytes);
		} catch (IOException e) {
			e.printStackTrace();
			say("Failed to store the document");
		}
	}

	//asymmetrically, with the server public key, to send the doc
	private static byte[] cipherDoc(byte[] docName) {
		
		byte[] cDoc = null;
		
		try {
			cDoc = AsymmetricCipher.cifrado(docName, trustStore, passphrase.toString(), "rsa_server_cert");

		} catch (Exception e) {

			e.printStackTrace();
		} 

		return cDoc;
	}

	//asymmetrically, with my private key, to receive the doc
	private static byte[] decypherDoc(byte[] cipheredDoc) {

		byte[] dDoc = null;

		try {
		
			dDoc = AsymmetricCipher.descifrado(cipheredDoc, keyStore, "123456", "rsa_client");
	
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
				| IllegalBlockSizeException | BadPaddingException | KeyStoreException | UnrecoverableEntryException
				| IOException e) {
		
			e.printStackTrace();
		}
		
		return dDoc;
	}

	//get the action the user wants to use
	private static int getAction() {

		int action = 4;

		say("Select action:");
		say("1) Register document");
		say("2) List documents");
		say("3) Recover document");
		say("4) Exit");
		say("...");

		action = Integer.parseInt(in.nextLine());

		return action;
	}

	//get arguments from invoke statement
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

	//ask the client about the type of confidentiality it wants
	private static String getConfType() {
		//TODO let the user choose the conf type

		String confType;

		//		say("øDo you want this file to be confidential?...");
		//		String res = in.nextLine();
		//		
		//		if(res.trim().equals("y") || res.trim().equals("yes")) {
		//			confType = "public";
		//		} else {
		//			confType = "private";
		//		}

		confType = "private";

		return confType;
	}

	//ask the client about what document it wants to send and obtain it
	private static Document getDocument() {
		//TODO dejar que el usuario pueda escoger el fichero

		Document doc;

		//		say("Type the name of the file that you want to send...");
		//		String fileName = in.nextLine();
		String fileName = "tux.png";

		File file = new File(fileName);
		byte[] fileContent;

		try {
			fileContent = Files.readAllBytes(file.toPath());
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

		doc = new Document();
		doc.setName(fileName);
		doc.setContent(fileContent);

		return doc;
	}

	private static X509Certificate getMyAuthCert() {
		
		return getMySignCert();
	}

	//to obtain the public key certificate for signing in order to send it to the server
	private static X509Certificate getMySignCert() {
		
		X509Certificate cert = null; 
		
		try {
			
			cert = (X509Certificate) keyStore.getCertificate("rsa_client");
		
		} catch (KeyStoreException e) {
		
			e.printStackTrace();
		}
		
		say("cert issuer " + cert.getIssuerX500Principal().getName());
		
		return cert;
	}

	//ask the user about the register identifier of the document it wants to recover 
	private static int getRID() {
		//TODO let the user
		
		int rid;
		
//		say("Type the RID of the document you want to recover...");
//		rid = Integer.parseInt(in.nextLine().trim());
		
		rid = 0;
		
		return rid;
	}

	private static String getSuite() throws NoSuchAlgorithmException {
		//TODO dejar que el usuario la escoja

		String selectedSuite;

		/*SSLContext ctx = SSLContext.getDefault();
		SSLSocketFactory factory = ctx.getSocketFactory();
		String[] suites = factory.getSupportedCipherSuites();

		say("Supported suites:");
		for(int i = 0; i < suites.length; i++) {

			String suite = suites[i];
			say(i + ") " + suite);
		}

		say("Please select a suite...");
		int suiteNumber = Integer.parseInt(in.nextLine());
		selectedSuite = suites[suiteNumber];
		 */

		selectedSuite = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";

		return selectedSuite;
	}

	//hash the document and store it in the hashedDocsTree
	private static byte[] hashDoc(byte[] documentBytes) {

		MessageDigest hash = null;

		byte[] md = null;
		
		try {
		
			hash = MessageDigest.getInstance("MD5");
			hash.update(documentBytes);
			md = hash.digest();
		
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		}
		
		return md;
	}

	private static Object listDocs() throws IOException, ClassNotFoundException {

		setPassphrase();
		setKeyStoreAndTrustStore();
		Socket socket = setConnection();

		if(socket == null) {

			say("Conection failed");
			return null;
		}

		String confType = getConfType();

		X509Certificate myAuthCert = getMyAuthCert();

		//TODO aquÌ la forma de imprimir puede falla (|n a la hora de construir la lista
		String response = sendListDocReq(confType, myAuthCert, socket);

		say(response);

		socket.close();

		return null;
	}

	private static Object recoverDoc() throws IOException, ClassNotFoundException {

		setPassphrase();
		setKeyStoreAndTrustStore();
		Socket socket = setConnection();

		if(socket == null) {

			say("Conection failed");
			return null;
		}

		X509Certificate myAuthCert = getMyAuthCert();

		int RID = getRID();

		Object response = sendRecDocReq(myAuthCert, RID, socket);

		if(response instanceof String) {

			say((String)response);

		} else {

			String timeStamp = ((Response) response).getTimeStamp();
			byte[] cypheredDoc = ((Response) response).getCypheredDoc();
			byte[] signedDoc = ((Response) response).getSignedDoc();
			byte[] serverSignCert = ((Response) response).getServerSignCert();

			if( ! validateServerSignCert(serverSignCert) ){

				say("CERTIFICADO DE REGISTRADOR INCORRECTO");

			} else {

				byte[] documentBytes = decypherDoc(cypheredDoc);

				byte[] sByClientDoc = signDoc(documentBytes);
				
				if( ! verifyServerSign(RID, timeStamp, documentBytes,  sByClientDoc, signedDoc)) {

					say("FALLO DE FIRMA DEL REGISTRADOR");

				} else {

					byte[] hashedDoc = hashDoc(documentBytes);
					byte[] OriginalHashedDoc = hashedDocsTree.get(RID);

					if( ! hashedDoc.equals(OriginalHashedDoc) ) {
						
						say("DOCUMENTO ALTERADO POR EL REGISTRADOR");

					} else {

						say("DOCUMENTO RECUPERADO CORRECTAMENTE " + RID + " " + timeStamp );
						storeDoc(hashedDoc, documentBytes);
					}
				}
			}
		}
		
		socket.close();
		
		return null;
	}

	private static Object registerDoc() throws IOException, ClassNotFoundException {

		setPassphrase();	
		setKeyStoreAndTrustStore();	
		Socket socket = setConnection();

		if(socket == null) {

			say("Conection failed");
			return null;
		}

		Document document = getDocument();

		if(document == null) {

			say("Unable to retrive document");
			return null;
		}

		String docName = document.getName();

		byte[] docContent = document.getContent();

		String confType = getConfType();

		byte[] cypheredDoc = cipherDoc(docContent);
		
		if(cypheredDoc == null) {
			
			say("Unable to encrypt the document");
			return null;
		}

		byte[] signedDoc = signDoc(cypheredDoc);

		X509Certificate mySignCert = getMySignCert();

		Object response = sendRegDocReq(docName, confType, cypheredDoc, signedDoc, mySignCert, socket);

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
				
				say("RID " + RID);
				say("timeStamp " + timeStamp);
				say("docContent " + Arrays.toString(docContent));
				say("signeDoc " + Arrays.toString(signedDoc));
				say("serverSignature " + Arrays.toString(serverSignature));
				
				//signed doc es el firmado aquÌ
				if( ! verifyServerSign(RID, timeStamp, docContent, signedDoc, serverSignature) ) {

					say("FIRMA INCORRECTA DEL REGISTRADOR");

				} else {

					say("Documento correctamente registrado con el numero " + RID + " " + timeStamp);

					byte[] hashedDoc = hashDoc(docContent);

					hashedDocsTree.put(RID, hashedDoc);
					
					say("Message digest = " + hashedDoc);

					//TODO para hacer las pruebas es mejor no borrar de momento
					//deleteDocAndSignature(docName);
				}
			}
		}

		socket.close();

		return null;
	}

	private static void deleteDocAndSignature(String docName) {
		
		File file = new File(docName);
		file.delete();
	}

	private static void say(String string) {

		System.out.println(string);
	}

	private static String sendListDocReq(String confType, X509Certificate myAuthCert, Socket socket) throws IOException, ClassNotFoundException{
		
		Request request = new Request(confType, myAuthCert);

		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

		out.write((int) 2);

		out.writeObject(request);
		
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
		
		//TODO hay que ver si eliminar esta parte
		int successcode = in.readInt();
		
		String response = (String) in.readObject();

		return response;	
	}

	private static Object sendRecDocReq(X509Certificate myAuthCert, int RID, Socket socket) throws IOException, ClassNotFoundException{

		Request request = new Request(myAuthCert, RID);

		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

		out.write((int) 3);

		out.writeObject(request);

		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
		
		int successcode = in.readInt();
		
		Object response = in.readObject();
		
		if(successcode == -1) {

			response = (String) response;
		} 
		else {
			
			response = (Response) response;
		}

		return response;
	}

	private static Object sendRegDocReq(String docName, String confType, byte[] cypheredDoc, byte[] signedDoc, X509Certificate mySignCert, Socket socket) throws IOException, ClassNotFoundException{

		Request request = new Request(docName, confType, cypheredDoc, signedDoc, mySignCert);

		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

		out.write((int) 1);

		out.writeObject(request);

		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
		
		int successcode = in.readInt();
		
		Object response = in.readObject();
		
		if(successcode == -1) {

			response = (String) response;
		} 
		else {
			
			response = (Response) response;
		}

		return response;
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

	private static void setKeyStoreAndTrustStore() {

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
		//TODO dejar que el usuario ponga su contraseÒa

		say("Insert KeyStore password...");

		//passphrase = in.nextLine().toCharArray();
		passphrase = "123456".toCharArray();
	}

	//with my private key, over the ciphered doc
	private static byte[] signDoc(byte[] cipheredDoc) {
		
		ClientSignVerifier csv = new ClientSignVerifier(keyStore, trustStore);
		
		csv.FirmarDocumento(cipheredDoc);
		
		return csv.getSign();
	}

	private static boolean validateServerSignCert(byte[] serverSignCert) {
		//TODO
		return true;
	}

	private static boolean verifyServerSign(int RID, String timeStamp, byte[] docContent, byte[] signedDoc, byte[] serverSignature) {

		boolean verify = false;
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		try {

			baos.write(RID);
			baos.write(timeStamp.getBytes());
			baos.write(docContent);
			baos.write(signedDoc);
			
		
		byte[] sigServC = baos.toByteArray();
		
		ClientSignVerifier csv = new ClientSignVerifier(keyStore, trustStore);
		
		verify = csv.VerifyServer(sigServC, serverSignature);
		
		} catch (Exception e) {
		
			e.printStackTrace();
		}
		
		return verify;
	}


}
