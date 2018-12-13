import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;

import com.sun.security.auth.X500Principal;

public class Server {

	static KeyStore keyStore;
	static KeyStore trustStore;
	static char[] passphrase;
	static int port;
	static String cypheringAlgorithm;
	static int nextRID = 0;

	public static void main(String[] args) {
	
		say("Getting arguments");
		if( getArgs(args) < 0) {
			return;
		}
		
		say("Setting net parameters");
		port = 5555;
	
		ServerSocket ss = prepareConection();
		
		while(true) {
	
			say("Waiting for conection");
			Socket socket;
			try {
				socket = ss.accept();
			} catch (IOException e2) {
				e2.printStackTrace();
				say("Connection failed");
				return;
			}
			
			say("Conection acepted");
			
			say("Waiting for request");
			Request request;
			try {
				request = getRequest(socket);
			} catch (IOException | ClassNotFoundException e) {
				e.printStackTrace();
				return;
			}
			
			int requestType = request.getType();
			
			switch (requestType) {
			case 1:
	
				try {
					registerDocResponse(request, socket);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
				break;
	
			case 2:
	
				try {
					listDocsResponse(request, socket);
				} catch (IOException e1) {
					e1.printStackTrace();
				}
				break;
	
			case 3:
	
				try {
					recoverDocResponse(request, socket);
				} catch (IOException | ClassNotFoundException e1) {
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
	private static byte[] cypherDoc(byte[] documentBytes, byte[] clientPublicKey) {
		//TODO
		return documentBytes;
	}

	//symmetric ciphering with secret key
	private static byte[] cypherDocForStorage(byte[] documentBytes) {
		//TODO
		return documentBytes;
	}

	//assymetrically to receive from the client
	private static byte[] decypherDoc(byte[] cypheredDoc) {
		//TODO
		return cypheredDoc;
	}

	//symmetric deciphering with secret key
	private static byte[] decypherDocForStorage(byte[] cypheredDoc) {
		//TODO hay que ver también dónde se incluye esto
		return cypheredDoc;
	}

	//tells whether or not a document is stored
	private static boolean docExists(int rID) {
		
		boolean found = false;
		
		String docsFolder = "./docs";
		File folder = new File(docsFolder);
		File[] listOfFiles = folder.listFiles();

		for (File file : listOfFiles) {
		    
			if (file.isFile()) {
		    	
				String fileName = file.getName();
		        System.out.println(fileName);
		        
		        if(fileName.contains("_" + rID + "_")) {
		        
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
			say("Server keyStoreFile KeyStorePassword trustStoreFile cypheringAlgorithm");
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
	
				cypheringAlgorithm = args[3];
	
			} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
	
				e.printStackTrace();
				return -1;
			}
	
			return 1;
		}
	}

	//obtains the client public key
	private static byte[] getClientPublicKey() {
		//TODO
		return "CLIENTPUBLICKEY".getBytes();
	}

	//recover a given stored doc
	private static Document getDoc(int rID) throws IOException, ClassNotFoundException {

		Document doc = new Document();

		FileInputStream fis = new FileInputStream("./docs/doc_" + rID + ".sig");

		ObjectInputStream ois = new ObjectInputStream(fis);
		doc = (Document) ois.readObject();

		ois.close();

		return doc;
	}

	private static Document getDoc(String fileName) {
		
		Document doc = new Document();
		
		try {
			
			FileInputStream fis = new FileInputStream("./docs/" + fileName);
			
			ObjectInputStream ois = new ObjectInputStream(fis);
			doc = (Document) ois.readObject();
			
			ois.close();
			
		} catch (ClassNotFoundException e) {
			
			e.printStackTrace();
			return null;
			
		} catch (IOException e) {
			
			e.printStackTrace();
			return null;
		}
		
		return doc;
	}
	
	private static byte[] getMyCertAuth() {
		//TODO
		return "MYCERTAUTH".getBytes();
	}

	//obtiene la clave privada del servidor para firmar el documento
	private static byte[] getMyPrivateKey() {
		//TODO
		return "MYPRIVATEKEY".getBytes();
	}

	//recover a list of the privatly stored documents
	private static String getPrivateDocs() {
		
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
			
			serializedList += privateDoc;
		}
		
		return serializedList;
	}

	//recover a list of the publicly stored documents
	private static String getPublicDocs() {

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
			
			serializedList += publicDoc;
		}
		
		return serializedList;
	}

	private static Request getRequest(Socket socket) throws IOException, ClassNotFoundException {
		
		Request request = null;
		
		ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
		
		int action = in.read();
		
		say(Integer.toString(action));
		
		switch (action) {
		case 1:
			
			say("Received recoverDoc request");
			request = (Request) in.readObject();
			request.setType(1);
			break;
			
		case 2:
			
			say("Received recoverDoc request");
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

	private static void listDocsResponse(Request request, Socket socket) throws IOException {
	
		String confType = request.getConfType();
		byte[] clientAuthCert = request.getAuthCert();
		
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		
		if( ! validateClientAuthCert(clientAuthCert) ) {
			
			String error = "CERTIFICADO INCORRECTO";
			
			say(error);
			sendErrorRes(error, out);
			
		} else {
			
			if( ! confType.equals("privado") ) {
				
				String  publicDocs = getPublicDocs();
				sendListDocRes(publicDocs, out);
				
			} else {
				
				String privateDocs = getPrivateDocs();
				sendListDocRes(privateDocs, out);
			}
		}
	}
	
	//TODO tengo la sensación de que si nos da que un documento no existe puede saltar una excepción y que no sea devuelto ningún mensaje al usuario
	private static void recoverDocResponse(Request request, Socket socket) throws IOException, ClassNotFoundException {
		
		byte[] clientAuthCert = request.getAuthCert();
		int RID = request.getRID();
		
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		
		if( ! docExists(RID) ) {
			
			String error = "DOCUMENTO NO EXISTENTE";
			sendErrorRes(error, out);
		
		} else {
			
			
			if( ! userHasPermit(RID, clientAuthCert) ) {
				
				String error = "ACCESO NO PERMITIDO";
				say(error);
				sendErrorRes(error, out);
				
			} else {
				
				Document doc = getDoc(RID);
				
				String timeStamp = doc.getTimeStamp();
				String confType = doc.getConfType();
				byte[] documentBytes = doc.getContent();
				
				if(confType.equals("privado")) {
				
					documentBytes = decypherDocForStorage(documentBytes);
				}
				
				byte[] clientPublicKey = getClientPublicKey();
				
				byte[] cypheredDoc = cypherDoc(documentBytes, clientPublicKey);
				
				//TODO aquÃ­ tengo la duda de si hay que enviar mÃ¡s cosas como una firma y el certificado del servidor para asÃ­ verificar en el cliente
				sendRecDocRes(confType, RID, timeStamp, cypheredDoc, out);
			}
		}
	}
	
	private static void registerDocResponse(Request request, Socket socket) throws IOException {
	
		//String docName = request.getDocName(); //hay que pensar si devolver esto para guardar después en el cliente
		String confType = request.getConfType();
		byte[] cypheredDoc = request.getCypheredDoc();
		byte[] docSignature = request.getSignedDoc();
		byte[] clientSignCert = request.getSignCert();
		
		ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
		
		if( ! validateClientSignCert(clientSignCert) ) {
			
			String error = "CERTIFICADO DE FIRMA INCORRECTO";
			
			say(error);
			sendErrorRes(error, out);
			
		} else {
			
			if( ! verifyDoc(cypheredDoc, docSignature) ) {
				
				String error = "FIRMA INCORRECTA";
				say(error);
				sendErrorRes(error, out);
			
			} else {
				
				byte[] documentBytes = decypherDoc(cypheredDoc);
				int RID = getRID();
				String timeStamp = getTimestamp();
				byte[] myPrivateKey = getMyPrivateKey();
				
				byte[] signedDoc = signDoc( RID, timeStamp, documentBytes, docSignature,myPrivateKey);
				
				if( confType.equals("privado") ) {
					
					documentBytes = cypherDocForStorage(documentBytes);
				}
				
				//para probar el registro
				Path path = Paths.get("doc_on_server");
				try {
					Files.write(path, documentBytes);
				} catch (IOException e) {
					e.printStackTrace();
					say("Failed to store the document");
				}
				
				//TODO clientSignCert debe ser un X508Certificate
				//String clientID = getClientID(clientSignCert);
				String clientID = "clientID";
				
				storeDoc(documentBytes, docSignature, RID, timeStamp, signedDoc, confType, clientID);
				
				byte[] myCertAuth = getMyCertAuth();
				
				sendRegDocRes(RID, timeStamp, signedDoc, myCertAuth, out);
			}
		}
	}
	
	//obtiene el identificador del usuario
	private static String getClientID(X509Certificate clientSignCert) {
		// TODO hacer que devuelva algo coherente
		
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
	private static void sendRecDocRes(String confType, int rid, String timeStamp, byte[] cypheredDoc, ObjectOutputStream out) throws IOException {

		Response response = new Response(confType, rid, timeStamp, cypheredDoc);
		out.writeInt((int)1);
		out.writeObject(response);
	}
	
	//elaborate register document response
	private static void sendRegDocRes(int RID, String timeStamp, byte[] signedDoc, byte[] myAuthCert, ObjectOutputStream out) throws IOException{
		
		Response response = new Response(RID, timeStamp, signedDoc, myAuthCert);
		out.writeInt((int)1);
		out.writeObject(response);
	}
	
	//firma el documento con la clave privada (esto es para almacenarlo)
	private static byte[] signDoc(int rID, String timeStamp, byte[] documentBytes, byte[] docSignature, byte[] myPrivateKey) {
		//TODO
		return documentBytes;
	}
	
	private static void storeDoc(byte[] documentBytes, byte[] docSignature, int rID, String timeStamp, byte[] signedDoc, String confType, String clientID) throws IOException {
		
		//ojo, sign doc es la firma del server, docSingature la del registrador
		Document doc = new Document(documentBytes, docSignature, rID, timeStamp, signedDoc, confType, clientID);
		
		FileOutputStream fout = new FileOutputStream("./docs/doc_" + rID + ".sig");
		ObjectOutputStream oos = new ObjectOutputStream(fout);
		oos.writeObject(doc);
		
		oos.close();
	}
	
	//tells whether the user has permit to access the document and whether the document is private or public
	private static boolean userHasPermit(int rID, byte[] clientAuthCert) throws ClassNotFoundException, IOException {
		
		//TODO clientAuthCert debe ser un X509Certificate
		//String clientID = getClientID(clientAuthCert);
		String clientID = "clientID";
		
		Document doc = getDoc(rID);
		
		boolean permit = false;
		
		if(doc.getConfType().equals("publico")){
			permit = true;
		} else if(clientID.equals(doc.getClientID())) {
			permit = true;
		}
		
		return permit;
	}
	
	private static boolean validateClientAuthCert(byte[] clientAuthCert) {
		//TODO
		return true;
	}
	
	private static boolean validateClientSignCert(byte[] clientSignCert) {
		//TODO
		return true;
	}
	
	private static boolean verifyDoc(byte[] cypheredDoc, byte[] docSignature) {
		//TODO
		return true;
	}
	
	private static ServerSocket prepareConection() {
	
		ServerSocket ss;
	
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
				return null;
			}    
	
			ss = ssf.createServerSocket(port);
			
			((SSLServerSocket)ss).setNeedClientAuth(true);
			

			
	    } catch (IOException e) {
	
	    	e.printStackTrace();
	    	return null;
		}
	
		return ss;
	}
	
}

