import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
	static Scanner in = new Scanner(System.in);
	static TreeMap<Integer, byte[]> hashedDocsTree = new TreeMap<Integer, byte[]>(); 
	static TreeMap<Integer, byte[]> signedDocsTree = new TreeMap<Integer, byte[]>();
	
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

			say("Getting action");
			int action = getAction();

			switch (action) {
			case 1:

				say("Register document");
				try {
					registerDoc();
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;

			case 2:

				say("List documents");
				try {
					listDocs();
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;

			case 3:

				say("Recover document");
				try {
					recoverDoc();
				} catch (Exception e) {
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
	private static void storeDoc(String docName, byte[] documentBytes) {
		
		Path path = Paths.get("recovered_" + docName);
		
		try {
			
			Files.write(path, documentBytes);
		
		} catch (IOException e) {
		
			e.printStackTrace();
			say("Failed to store the document");
		}
	}

	//asymmetrically, with the server public key, to send the doc
	private static byte[] cipherDoc(byte[] docName) throws Exception {
		
		byte[] cDoc = null;
		
		cDoc = AsymmetricCipher.cifrado(docName, trustStore, passphrase.toString(), "rsa_server_cert");

		return cDoc;
	}

	//asymmetrically, with my private key, to receive the doc
	private static byte[] decipherDoc(byte[] cipheredDoc) throws Exception {

		byte[] dDoc = null;

		dDoc = AsymmetricCipher.descifrado(cipheredDoc, keyStore, "123456", "rsa_client");

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

	//get arguments
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

	//ask the client about the type of confidentiality he wants
	private static String getConfType() {

		String confType;

		say("¿Is confidentiality private?...");
		String res = in.nextLine();

		if(res.trim().equals("y") || res.trim().equals("yes")) {
			confType = "public";
		} else {
			confType = "private";
		}
		
		return confType;
	}

	//ask the client about what document wants to send and obtain it
	private static Document getDocument() throws Exception {

		Document doc;

		say("Type the name of the file that you want to send...");
		String fileName = in.nextLine();

		File file = new File(fileName);
		byte[] fileContent;

		fileContent = Files.readAllBytes(file.toPath());

		doc = new Document();
		doc.setName(fileName);
		doc.setContent(fileContent);

		return doc;
	}

	private static X509Certificate getMyAuthCert() throws Exception {
		
		return getMySignCert();
	}

	//to obtain the public key certificate for signing in order to send it to the server
	private static X509Certificate getMySignCert() throws Exception {
		
		X509Certificate cert = null; 
		
		cert = (X509Certificate) keyStore.getCertificate("rsa_client");
		
		return cert;
	}

	//ask the user about the register identifier of the document it wants to recover 
	private static int getRID() {
		
		int rid;
		
		say("Type the RID of the document you want to recover...");
		rid = Integer.parseInt(in.nextLine().trim());
		
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
	private static byte[] hashDoc(byte[] documentBytes) throws Exception {

		MessageDigest hash;

		byte[] md;
		
		hash = MessageDigest.getInstance("MD5");
		hash.update(documentBytes);
		md = hash.digest();
		
		return md;
	}

	private static void listDocs() throws Exception {

		setPassphrase();
		setKeyStoreAndTrustStore();

		say("Connectig");
		Socket socket = setConnection();

		say("Builing request");
		String confType = getConfType();

		X509Certificate myAuthCert = getMyAuthCert();

		say("Sending");
		String response = sendListDocReq(confType, myAuthCert, socket);

		say("Response received");
		say(response);

		socket.close();

		return;
	}

	private static void recoverDoc() throws Exception {

		setPassphrase();
		setKeyStoreAndTrustStore();

		say("Connecting");
		Socket socket = setConnection();

		say("Building request");
		X509Certificate myAuthCert = getMyAuthCert();

		int rid = getRID();

		say("Sending");
		Object response = sendRecDocReq(myAuthCert, rid, socket);

		say("Response received");
		if(response instanceof String) {

			say((String)response);

		} else {

			String docName = ((Response) response).getDocName();
			String timeStamp = ((Response) response).getTimeStamp();
			byte[] cipheredDoc = ((Response) response).getCipheredDoc();
			byte[] serverSignature = ((Response) response).getServerSignature();
			byte[] serverSignCert = ((Response) response).getServerSignCert();

			say("Validating");
			if( ! validateServerSignCert(serverSignCert) ){

				say("Certificado de registrador incorrecto");

			} else {

				byte[] documentBytes = decipherDoc(cipheredDoc);

				byte[] signedDoc = signedDocsTree.get(rid);
				
				say("Verifying");
				if( ! verifyServerSign(rid, timeStamp, documentBytes,  signedDoc, serverSignature)) {

					say("Fallo de firma del registrador");

				} else {

					say("Checking document");
					byte[] hashedDoc = hashDoc(documentBytes);

					byte[] originalHashedDoc = hashedDocsTree.get(rid);

					if( ! Arrays.equals(hashedDoc, originalHashedDoc) ) {
						
						say("Documento alterado por el registrador");

					} else {

						say("Documento recuperado correctamente: rid: " + rid + " timestamp: " + timeStamp );
						storeDoc(docName, documentBytes);
					}
				}
			}
		}
		
		socket.close();
		
		return;
	}

	private static void registerDoc() throws Exception {

		setPassphrase();	
		setKeyStoreAndTrustStore();
		
		say("Connecting");
		Socket socket = setConnection();

		say("Building request");
		Document document = getDocument();

		String docName = document.getName();

		byte[] docContent = document.getContent();

		String confType = getConfType();

		byte[] cipheredDoc = cipherDoc(docContent);
		
		byte[] signedDoc = signDoc(cipheredDoc);

		X509Certificate mySignCert = getMySignCert();

		say("Sending");
		Object response = sendRegDocReq(docName, confType, cipheredDoc, signedDoc, mySignCert, socket);

		say("Response received");
		if(response instanceof String) {

			say((String)response);

		} else {

			int rid = ((Response) response).getRID();
			String timeStamp = ((Response)response).getTimeStamp();
			byte[] serverSignature = ((Response)response).getServerSignature();
			byte[] serverSignCert = ((Response)response).getServerSignCert();

			say("Validating");
			if( ! validateServerSignCert(serverSignCert) ) {

				say("Certificado de registrador icorrecto");

			} else {
				
				say("Verifying");
				if( ! verifyServerSign(rid, timeStamp, docContent, signedDoc, serverSignature) ) {

					say("Firma incorrecta del registrador");

				} else {

					say("Documento correctamente registrado con el numero " + rid + " " + timeStamp);

					say("Hashing document");
					byte[] hashedDoc = hashDoc(docContent);
					hashedDocsTree.put(rid, hashedDoc);
					
					signedDocsTree.put(rid, signedDoc);
					
					say("Deleting document");
					deleteDocAndSignature(docName);
				}
			}
		}

		socket.close();

		return;
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
		
		int successcode = in.readInt();
		
		String response = (String) in.readObject();

		return response;	
	}

	private static Object sendRecDocReq(X509Certificate myAuthCert, int rid, Socket socket) throws IOException, ClassNotFoundException{

		Request request = new Request(myAuthCert, rid);

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

	private static Object sendRegDocReq(String docName, String confType, byte[] cipheredDoc, byte[] signedDoc, X509Certificate mySignCert, Socket socket) throws IOException, ClassNotFoundException{

		Request request = new Request(docName, confType, cipheredDoc, signedDoc, mySignCert);

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

	private static Socket setConnection() throws Exception {

		SSLSocket socket;

		SSLSocketFactory factory;

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

		socket = (SSLSocket)factory.createSocket(host, port);

		String[] suiteArray = {suite};
		socket.setEnabledCipherSuites(suiteArray);

		socket.startHandshake();

		return socket;
	}

	private static void setKeyStoreAndTrustStore() throws Exception {

			keyStore = KeyStore.getInstance("JCEKS");
			keyStore.load(new FileInputStream(keyStoreName), passphrase);

			trustStore = KeyStore.getInstance("JCEKS");
			trustStore.load(new FileInputStream(trustStoreName), passphrase);
	}

	private static void setPassphrase() {
		//TODO dejar que el usuario ponga su contraseña
		//later
		
		//say("Insert KeyStore password...");
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

	private static boolean verifyServerSign(int rid, String timeStamp, byte[] docContent, byte[] signedDoc, byte[] serverSignature) throws Exception {

		boolean verify;
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		baos.write(rid);
		baos.write(timeStamp.getBytes());
		baos.write(docContent);
		baos.write(signedDoc);
					
		byte[] sigServC = baos.toByteArray();
		
		ClientSignVerifier csv = new ClientSignVerifier(keyStore, trustStore);
		
		verify = csv.VerifyServer(sigServC, serverSignature);
		
		return verify;
	}
	
}
