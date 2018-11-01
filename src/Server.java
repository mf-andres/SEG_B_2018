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
	static String cypheringAlgorithm;

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
			Request request  = getRequest();
			int requestType = request.getRequestType();
			
			switch (requestType) {
			case 1:

				registerDocResponse(request);
				break;

			case 2:

				listDocsResponse(request);
				break;

			case 3:

				recoverDocResponse(request);
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

	private static Request getRequest() {
		
		return null;
	}

	private static void recoverDocResponse(Request request) {
		
		byte[] clientAuthCert = request.getClientAuthCert();
		int RID = request.getRID();
		
		if( ! docExists(RID) ) {
			
			String error = "DOCUMENTO NO EXISTENTE";
			sendErrorRes(error);
		
		} else {
			
			
			if( ! userHasPermit(RID, clientAuthCert) ) {
				
				String error = "ACCESO NO PERMITIDO";
				say(error);
				sendErrorRes(error);
				
			} else {
				
				Document doc = getDoc(RID);
				
				String timeStamp = doc.getTimeStamp();
				String confType = doc.getConfType();
				byte[] documentBytes = doc.getBytes();
				
				if(confType.equals("privado")) {
				
					documentBytes = decypherDoc(documentBytes);
				}
				
				byte[] cypheredDoc = cypherDoc(documentBytes);
				
				//TODO aquí tengo la duda de si hay que enviar más cosas como una firma y el certificado del servidor para así verificar en el cliente
				sendRecDocRes(confType, RID, timeStamp, cypheredDoc);
			}
		}
	}

	private static byte[] cypherDoc(byte[] documentBytes) {
		return null;
	}

	private static void listDocsResponse(Request request) {
	
		String confType = request.getConfType();
		byte[] clientAuthCert = request.getClientAuthCert();
		
		if( ! validateClientAuthCert(clientAuthCert) ) {
			
			String error = "CERTIFICADO INCORRECTO";
			
			say(error);
			sendErrorRes(error);
		} else {
			
			if( ! confType.equals("privado") ) {
				
				String  publicDocs = getPublicDocs();
				sendListDocRes(publicDocs);
				
			} else {
				
				String privateDocs = getPrivateDocs();
				sendListDocRes(privateDocs);
			}
		}
	}

	private static boolean validateClientAuthCert(byte[] clientAuthCert) {

		return false;
	}

	private static void registerDocResponse(Request request) {
	
		String docName = request.getDocName();
		String confType = request.getConfType();
		byte[] cypheredDoc = request.getCypheredDoc();
		byte[] docSignature = request.getDocSignature();
		byte[] clientSignCert = request.getClientSignCert();
		
		if( ! validateClientSignCert(clientSignCert) ) {
			
			String error = "CERTIFICADO DE FIRMA INCORRECTO";
			
			say(error);
			sendErrorRes(error);
			
		} else {
			
			if( ! verifyDoc(cypheredDoc, docSignature) ) {
				
				say("FIRMA INCORRECTA");
			
			} else {
				
				byte[] documentBytes = decypherDoc(cypheredDoc);
				int RID = getRID();
				String timeStamp = getTimestamp();
				byte[] myPrivateKey = getMyPrivateKey();
				
				byte[] signedDoc = signDoc( RID, timeStamp,documentBytes, docSignature,myPrivateKey);
				
				if( confType.equals("privado") ) {
					
					documentBytes = cypherDocForStorage(documentBytes);
				}
				
				storeDoc(documentBytes, docSignature, RID, timeStamp, signedDoc);
				
				byte[] myCertAuth = getMyCertAuth();
				
				sendRegDocRes(RID, timeStamp, signedDoc, myCertAuth);
			}
		}
	}

	private static byte[] getMyCertAuth() {
		return null;
	}

	private static void sendErrorRes(String error) {
		
	}

	//firma el documento con la clave privada
	private static byte[] signDoc(int rID, String timeStamp, byte[] documentBytes, byte[] myPrivateKey, byte[] myPrivateKey2) {
		return null;
	}

	//obtiene la clave privada del servidor para firmar el documento
	private static byte[] getMyPrivateKey() {
		return null;
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

	private static boolean validateClientSignCert(byte[] clientSignCert) {
		
		return false;
	}

	private static boolean verifyDoc(byte[] cypheredDoc, byte[] docSignature) {
		
		return false;
	}
	
	private static byte[] decypherDoc(byte[] cypheredDoc) {
		
		return null;
	}
	
	//get an int that identifies the document
	private static int getRID(){
	
		return 0;
	}
	
	//get a string that specifies the moment the document was stored
	private static String getTimestamp() {
		
		return null;
	}
	
	//symmetric cyphering with secret key
	private static byte[] cypherDocForStorage(byte[] documentBytes) {
		
		return null;
	}
	
	private static void decypherDocForStorage() {
		
	}
	
	private static void storeDoc(byte[] documentBytes, byte[] docSignature, int rID, String timeStamp, byte[] signedDoc) {
		
	}
	
	//tells whether or not a document is stored
	private static boolean docExists(int rID) {
		
		return false;
	}
	
	//tells whether the user has permit to access the document and whether the document is private or public
	private static boolean userHasPermit(int rID, byte[] clientAuthCert) {
		
		return false;
	}
	
	//elaborate register document response
	private static void sendRegDocRes(int RID, String timeStamp, byte[] signedDoc, byte[] myCertAuth){
		
	}
	
	//elaborate list documents response
	private static void sendListDocRes(String publicDocs) {
		
	}
	
	//elaborate recover document response
	private static void sendRecDocRes(String confType, int rID, String timeStamp, byte[] cypheredDoc) {
		
	}
	
	//recover a list of the publicly stored documents
	private static String getPublicDocs() {
		
		return null;
	}
	
	//recover a list of the privatly stored documents
	private static String getPrivateDocs() {
		
		return null;
	}
	
	//recover a given stored doc
	private static Document getDoc(int rID) {
		return null;
		
	}
	
	//obtains the client public key
	private static void getClientPublicKey() {
		
	}
	
}

