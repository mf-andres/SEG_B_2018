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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
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
	static Scanner in = new Scanner(System.in);;
	static TreeMap<Integer, byte[]> hashedDocsTree = new TreeMap<Integer, byte[]>(); //arbol que almacena valores hash de los documentos registrados junto a su número de registro

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
	private static byte[] cypherDoc(byte[] documentBytes, byte[] serverPublicKey) {
		//TODO
		return documentBytes;
	}

	//asymmetrically, with my private key, to receive the doc
	private static byte[] decypherDoc(byte[] cypheredDoc, byte[] myPrivateKey) {
		//TODO
		return cypheredDoc;
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

		//		say("�Do you want this file to be confidential?...");
		//		String res = in.nextLine();
		//		
		//		if(res.trim().equals("y") || res.trim().equals("yes")) {
		//			confType = "public";
		//		} else {
		//			confType = "private";
		//		}

		confType = "public";

		return confType;
	}

	//ask the client about what document it wants to send and obtain it
	private static Document getDocument() {
		//TODO dejar que el usuario pueda escoger el fichero

		Document doc;

		//		say("Type the name of the file that you want to send...");
		//		String fileName = in.nextLine();
		String fileName = "turtle.jpg";

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

	private static byte[] getMyAuthCert() {
		//TODO
		return "MYAUTHCERT".getBytes();
	}

	//to sign the doc
	private static byte[] getMyPrivateKey() {
		//TODO
		return "PRIVATEKEY".getBytes();	
	}

	//to obtain the public key certificate for signing in order to send it to the server
	private static byte[] getMySignCert() {
		//TODO
		return "MYSIGNCERT".getBytes();
	}

	//ask the user about the register identifier of the document it wants to recover 
	private static int getRID() {
		//TODO
		
		int rid;
		
//		say("Type the RID of the document you want to recover...");
//		rid = Integer.parseInt(in.nextLine().trim());
		
		rid = 1;
		
		return rid;
	}

	private static byte[] getServerPublicKey(){
		//TODO 
		return "SERVERPUBLICKEY".getBytes();
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

		byte[] myAuthCert = getMyAuthCert();

		// TODO aquí la forma de imprimir la respuesta quizá no sea la más indicada
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

		byte[] myAuthCert = getMyAuthCert();

		int RID = getRID();

		Object response = sendRecDocReq(myAuthCert, RID, socket);

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
			byte[] serverSignCert = ((Response) response).getServerSignCert();

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

					//TODO esto es para la prueba, una vez se devuelva un documento v�lido hay que cambiarlo
					//if( ! hashedDoc.equals(OriginalHashedDoc) ) {
					if(false) {
						
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
		}

		String docName = document.getName();

		byte[] docContent = document.getContent();

		String confType = getConfType();

		byte[] serverPublicKey = getServerPublicKey();

		byte[] myPrivateKey = getMyPrivateKey();

		byte[] cypheredDoc = cypherDoc(docContent, serverPublicKey);

		byte[] signedDoc = signDoc(cypheredDoc, myPrivateKey);

		byte[] mySignCert = getMySignCert();

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

				if( ! verifyServerSign(serverSignature, docContent, signedDoc) ) {

					say("FIRMA INCORRECTA DEL REGISTRADOR");

				} else {

					say("Documento correctamente registrado con el numero " + RID + " " + timeStamp);

					byte[] hashedDoc = hashDoc(docContent);

					hashedDocsTree.put(RID, hashedDoc);

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

	private static String sendListDocReq(String confType, byte[] myAuthCert, Socket socket) throws IOException, ClassNotFoundException{
		
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

	private static Object sendRecDocReq(byte[] myAuthCert, int RID, Socket socket) throws IOException, ClassNotFoundException{

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

	private static Object sendRegDocReq(String docName, String confType, byte[] cypheredDoc, byte[] signedDoc, byte[] mySignCert, Socket socket) throws IOException, ClassNotFoundException{

		Request request = new Request(docName, confType, cypheredDoc, signedDoc);

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
		//TODO dejar que el usuario ponga su contrase�a

		say("Insert KeyStore password...");

		//passphrase = in.nextLine().toCharArray();
		passphrase = "123456".toCharArray();
	}

	//with my private key, over the ciphered doc
	private static byte[] signDoc(byte[] cypheredDoc, byte[] myPrivateKey) {
		//TODO
		return cypheredDoc;
	}

	private static boolean validateServerSignCert(byte[] serverSignCert) {
		//TODO
		return true;
	}

	private static boolean verifyServerSign(byte[] serverSignature, byte[] documentBytes, byte[] signedDoc) {
		//TODO esta función es probable que esté mal definida. Hay que tener en cuenta la respuesta del servidor a recgiste doc
		//hay que estudiarlo
		return true;
	}


}
