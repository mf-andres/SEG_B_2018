import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
	static int nextRID = 0;

	public static void main(String[] args) {
	
		say("Getting arguments");
		if( getArgs(args) < 0) {
			return;
		}
		
		say("Setting net parameters");
		port = 5555;
	
		say("Preparing connection");
		ServerSocket ss;
		try {
			ss = prepareConection();
		} catch (Exception e3) {
			e3.printStackTrace();
			return;
		}
		
		while(true) {
	
			say("Waiting for conection");
			Socket socket;
			try {
				socket = ss.accept();
			} catch (IOException e2) {
				e2.printStackTrace();
				say("Connection failed");
				continue;
			}
			
			say("Conection acepted");
			
			say("Waiting for request");
			Request request;
			try {
				request = getRequest(socket);
			} catch (Exception e) {
				e.printStackTrace();
				continue;
			}
			
			int requestType = request.getType();
			
			switch (requestType) {
			case 1:
	
				say("Register document");
				try {
					registerDocResponse(request, socket);
				} catch (Exception e) {
					e.printStackTrace();
				}
				break;
	
			case 2:
	
				say("List documents");
				try {
					listDocsResponse(request, socket);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				break;
	
			case 3:
	
				say("Recover document");
				try {
					recoverDocResponse(request, socket);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				break;
	
			default:
	
				say("Something went odd");
				say("Goodbye");
				return;
			}
			
			try {
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	//asymmetrically to send to the client
	private static byte[] cipherDoc(byte[] documentBytes) throws Exception {
		
		byte[] cDoc = null;

		cDoc = AsymmetricCipher.cifrado(documentBytes, trustStore, passphrase.toString(), "rsa_client_cert");

		return cDoc;
	}

	//symmetric ciphering with secret key
	private static byte[] cipherDocForStorage(byte[] documentBytes) throws Exception {

		byte[] cDoc = null;
		
		cDoc = SymmetricCipher.cifrado(documentBytes, keyStore, "123456", "aes_server");
		
		return cDoc;
	}

	//assymetrically to receive from the client
	private static byte[] decipherDoc(byte[] cipheredDoc) throws Exception {

		byte[] dDoc = null;
		
		dDoc = AsymmetricCipher.descifrado(cipheredDoc, keyStore, passphrase.toString(), "rsa_server");
		
		return dDoc;
	}

	//symmetric deciphering with secret key
	private static byte[] decipherDocForStorage(byte[] cipheredDoc) throws Exception {

		byte[] dDoc = null;
			
		dDoc = SymmetricCipher.descifrado(cipheredDoc, keyStore, "123456", "aes_server");
	
		return dDoc;
	}

	//tells whether or not a document is stored
	private static boolean docExists(int rID) throws Exception{
		
		boolean found = false;
		
		String docsFolder = "./docs";
		File folder = new File(docsFolder);
		File[] listOfFiles = folder.listFiles();

		for (File file : listOfFiles) {
		    
			if (file.isFile()) {
		    	
				String fileName = file.getName();
		        System.out.println(fileName);
		        
		        Document doc = getDoc(fileName);
		        
		        if(doc.getrID() == rID) {
		        
		        	found = true;
		        	break;
		        }
		    }
		}

		return found;
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

	//recover a given stored doc
	private static Document getDoc(int rID) throws Exception {

		String docsFolder = "./docs";
		File folder = new File(docsFolder);
		File[] listOfFiles = folder.listFiles();

		for (File file : listOfFiles) {
		    
			if (file.isFile()) {
		    	
				String fileName = file.getName();
		        System.out.println(fileName);
		        
		        Document doc = getDoc(fileName);
		        
		        if(doc.getrID() == rID){
		        
		        	return doc;
		        }
			}
		}
		
		return null;
	}

	private static Document getDoc(String fileName) throws Exception {
		
		Document doc = new Document();

		FileInputStream fis = new FileInputStream("./docs/" + fileName);

		ObjectInputStream ois = new ObjectInputStream(fis);
		doc = (Document) ois.readObject();

		ois.close();

		return doc;
	}
	
	private static byte[] getMyCertAuth() {
		//TODO
		return "MYCERTAUTH".getBytes();
	}

	//recover a list of the privately stored documents
	private static String getPrivateDocs() throws Exception {
		
		ArrayList<String> privateDocs = new ArrayList<String>();
		
		String docsFolder = "./docs";
		File folder = new File(docsFolder);
		File[] listOfFiles = folder.listFiles();

		for (File file : listOfFiles) {
		    
			if (file.isFile()) {
		    	
				String fileName = file.getName();
		        System.out.println(fileName);
		        
		        Document doc = getDoc(fileName);
		        
		        if(doc.getConfType().equals("private")){
		        
		        	privateDocs.add(fileName);
		        }
			}
		}
			
		String serializedList = "";
		for(String privateDoc : privateDocs) {
			
			serializedList += "\n";
			serializedList += privateDoc;
		}
		
		return serializedList;
	}

	//recover a list of the publicly stored documents
	private static String getPublicDocs() throws Exception {

		ArrayList<String> publicDocs = new ArrayList<String>();
		
		String docsFolder = "./docs";
		File folder = new File(docsFolder);
		File[] listOfFiles = folder.listFiles();

		for (File file : listOfFiles) {
		    
			if (file.isFile()) {
		    	
				String fileName = file.getName();
		        System.out.println(fileName);
		        
		        Document doc = getDoc(fileName);
		        
		        if(doc.getConfType().equals("public")){
		        	
		        	publicDocs.add(fileName);
		        }
			}
		}
			
		String serializedList = "";
		for(String publicDoc : publicDocs) {
			
			serializedList += "\n";
			serializedList += publicDoc;
		}
		
		return serializedList;
	}

	private static Request getRequest(Socket socket) throws Exception {
		
		Request request = null;
		
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
		
		int action = in.read();
		
		say(Integer.toString(action));
		
		switch (action) {
		case 1:
			
			say("Received registerDoc request");
			request = (Request) in.readObject();
			request.setType(1);
			break;
			
		case 2:
			
			say("Received listDocs request");
			request = (Request) in.readObject();
			request.setType(2);
			break;
			
		case 3:
			
			say("Received recoverDoc request");
			request = (Request) in.readObject();
			request.setType(3);
			break;

		default:
			
			say("Something odd happened receiving request");
			break;
		}
		
		return request;
	}

	//get an int that identifies the document
	private static int getRID(){
		return nextRID++;
	}

	//get a string that specifies the moment the document was stored
	private static String getTimestamp() {
		
		Timestamp timestamp = new Timestamp(System.currentTimeMillis());
		return timestamp.toString();
	}

	private static void listDocsResponse(Request request, Socket socket) throws Exception {
	
		String confType = request.getConfType();
		X509Certificate clientAuthCert = request.getAuthCert();
		
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		
		say("Validating");
		if( ! validateClientAuthCert(clientAuthCert) ) {
			
			String error = "Certificado incorrecto";
			
			say(error);
			sendErrorRes(error, out);
			
		} else {
			
			say("Sending response");
			if( ! confType.equals("private") ) {
				
				String  publicDocs = getPublicDocs();
				sendListDocRes(publicDocs, out);
				
			} else {
				
				String privateDocs = getPrivateDocs();
				sendListDocRes(privateDocs, out);
			}
		}
	}
	
	private static void recoverDocResponse(Request request, Socket socket) throws Exception {
		
		X509Certificate clientAuthCert = request.getAuthCert();
		int RID = request.getRID();
		
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		
		say("Checkig document existence");
		if( ! docExists(RID) ) {
			
			String error = "Documento no existente";
			sendErrorRes(error, out);
		
		} else {
			
			say("Checking user permits");
			if( ! userHasPermit(RID, clientAuthCert) ) {
				
				String error = "Acceso no permitido";
				say(error);
				sendErrorRes(error, out);
				
			} else {
				
				say("Recovering document");
				Document doc = getDoc(RID);
				
				String docName = doc.getName();
				String timeStamp = doc.getTimeStamp();
				String confType = doc.getConfType();
				byte[] documentBytes = doc.getDocumentBytes();
				byte[] serverSignature = doc.getServerSignature();
				
				if(confType.equals("private")) {
				
					documentBytes = decipherDocForStorage(documentBytes);
				}
				
				byte[] cipheredDoc = cipherDoc(documentBytes);

				say("Sending response");
				sendRecDocRes(docName, confType, RID, timeStamp, cipheredDoc, serverSignature, out);
			}
		}
	}
	
	private static void registerDocResponse(Request request, Socket socket) throws Exception {
	
		String docName = request.getDocName();
		String confType = request.getConfType();
		byte[] cipheredDoc = request.getCipheredDoc();
		byte[] signedDoc = request.getSignedDoc();
		X509Certificate clientSignCert = request.getSignCert();
		
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		
		say("Validating");
		if( ! validateClientSignCert(clientSignCert) ) {
			
			String error = "Certificado de firma incorrecto";
			
			say(error);
			sendErrorRes(error, out);
			
		} else {
			
			say("Verifying");
			if( ! verifyDoc(cipheredDoc, signedDoc) ) {
				
				String error = "Firma incorrecta";
				say(error);
				sendErrorRes(error, out);
			
			} else {
				
				say("Preparing document for storage");
				byte[] documentBytes = decipherDoc(cipheredDoc);
				
				int RID = getRID();
				String timeStamp = getTimestamp();
				
				byte[] serverSignature = signDoc( RID, timeStamp, documentBytes, signedDoc);
				
				if( confType.equals("private") ) {
					
					documentBytes = cipherDocForStorage(documentBytes);
				}
								
				String clientID = getClientID(clientSignCert);
				
				say("Storing document");
				storeDoc(docName, documentBytes, signedDoc, RID, timeStamp, serverSignature, confType, clientID);
				
				byte[] myCertAuth = getMyCertAuth();
				
				say("Seding response");
				sendRegDocRes(RID, timeStamp, serverSignature, myCertAuth, out);
			}
		}
	}
	
	//obtiene el identificador del usuario
	private static String getClientID(X509Certificate clientSignCert) {
		
		return clientSignCert.getIssuerX500Principal().getName();
	}

	private static void say(String string) {
		
		System.out.println(string);
	}
	
	private static void sendErrorRes(String error, ObjectOutputStream out) throws IOException {
		
		out.writeInt((int)-1);
		out.writeObject(error);
	}
	
	//elaborate list documents response
	private static void sendListDocRes(String publicDocs, ObjectOutputStream out) throws IOException {
		
		out.writeInt((int)1);
		out.writeObject(publicDocs);
	}
	
	//elaborate recover document response
	private static void sendRecDocRes(String docName, String confType, int rid, String timeStamp, byte[] cipheredDoc, byte[] serverSignature, ObjectOutputStream out) throws IOException {

		Response response = new Response(docName, confType, rid, timeStamp, cipheredDoc, serverSignature);
		out.writeInt((int)1);
		out.writeObject(response);
	}
	
	//elaborate register document response
	private static void sendRegDocRes(int RID, String timeStamp, byte[] serverSignature, byte[] myAuthCert, ObjectOutputStream out) throws IOException{
		
		Response response = new Response(RID, timeStamp, serverSignature, myAuthCert);
		out.writeInt((int)1);
		out.writeObject(response);
	}
	
	//firma el documento con la clave privada (esto es para almacenarlo)
	private static byte[] signDoc(int rID, String timeStamp, byte[] documentBytes, byte[] docSignature) throws Exception {

		ServerSignVerifier ssv = new ServerSignVerifier(keyStore, trustStore);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		baos.write(rID);
		baos.write(timeStamp.getBytes());
		baos.write(documentBytes);
		baos.write(docSignature);

		documentBytes = baos.toByteArray();
		
		ssv.ServerSign(documentBytes);
		
		documentBytes = ssv.getServerSign();
		
		return documentBytes;
	}
	
	private static void storeDoc(String docName, byte[] documentBytes, byte[] signedDoc, int rID, String timeStamp, byte[] serverSignature, String confType, String clientID) throws IOException {

		Document doc = new Document(docName, documentBytes, serverSignature, rID, timeStamp, signedDoc, confType, clientID);
		
		FileOutputStream fout = new FileOutputStream("./docs/" + docName + ".sig");
		ObjectOutputStream oos = new ObjectOutputStream(fout);
		oos.writeObject(doc);
		
		oos.close();
	}
	
	//tells whether the user has permit to access the document and whether the document is private or public
	private static boolean userHasPermit(int rID, X509Certificate clientAuthCert) throws Exception {
		
		String clientID = getClientID(clientAuthCert);
		
		Document doc = getDoc(rID);
		
		boolean permit = false;
		
		if(doc.getConfType().equals("public")){
			permit = true;
		} else if(clientID.equals(doc.getClientID())) {
			permit = true;
		}
		
		return permit;
	}
	
	private static boolean validateClientAuthCert(X509Certificate clientAuthCert) {
		//TODO
		return true;
	}
	
	private static boolean validateClientSignCert(X509Certificate clientSignCert) {
		//TODO
		return true;
	}
	
	private static boolean verifyDoc(byte[] cipheredDoc, byte[] docSignature) throws Exception {

		boolean verify = false;
		
		ServerSignVerifier ssv = new ServerSignVerifier(keyStore, trustStore);
		
		verify = ssv.VerifyClientSign(cipheredDoc, docSignature);
		
		return verify;
	}
	
	private static ServerSocket prepareConection() throws Exception {

		ServerSocket ss;

		SSLServerSocketFactory ssf;

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

		ss = ssf.createServerSocket(port);

		((SSLServerSocket)ss).setNeedClientAuth(true);

		return ss;
	}
	
}

