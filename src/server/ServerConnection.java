package server;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.LinkedList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import messages.ListRequest;
import messages.ListResponse;
import messages.RegisterRequest;
import messages.RegisterResponse;
import messages.RetrieveRequest;
import messages.RetrieveResponse;
import messages.TimestampRequest;
import messages.TimestampResponse;

public class ServerConnection extends Thread {

	private Socket clientSocket;
	private String cypherAlgorithm;
	private ServerSignVerifier serverSigner = new ServerSignVerifier(GetKeyStorePath("serverKeyStore"),
			GetKeyStorePath("serverTrustStore"));
	private static ArrayList<Integer> registerIDs = new ArrayList<>();
	private static ArrayList<DataBase> dataBase = new ArrayList<>();
	private ObjectInputStream receivedObject;
	private ObjectOutputStream sendObject;

	public ServerConnection(Socket client, String algorithm) {

		this.clientSocket = client;
		this.cypherAlgorithm = algorithm;
	}

	public void run() {

		try {
			System.out.println("\tConnection established!!!\n");
			BufferedReader receivedData = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			sendObject = new ObjectOutputStream(clientSocket.getOutputStream());
			receivedObject = new ObjectInputStream(clientSocket.getInputStream());

			while (true) {
				String opcion = receivedData.readLine();
				int opc = Integer.parseInt(opcion);
				System.out.println("NEW OPERATION\n");
				switch (opc) {
				case 1:
					RegisterDocument();
					break;
				case 2:
					RetrieveDocument();
					break;
				case 3:
					ListDocuments();
					break;
				default:
					System.out.println("Opcion no valida");
					break;
				}
			}
		} catch (IOException e) {
			System.out.println("\n\tClient disconnected because:\n\t" + e.getMessage());
		}
	}

	private void RegisterDocument() {
		int id = GetNewRegisterId();
		try {
			RegisterRequest registerRequest = (RegisterRequest) receivedObject.readObject();
			String ownerId = registerRequest.getOwnerId();
			String docName = registerRequest.getDocName();
			String isPrivate = registerRequest.isPrivate() ? "privado" : "publico";
			// DEBUG
			System.out.println("REGISTRO");
			System.out.println("\tIdRegistro:: " + id);
			System.out.println("\tPropietario:: " + ownerId);
			System.out.println("\tNombredoc:: " + docName);
			System.out.println("\tTipo de confidencialidad:: " + isPrivate);
			int TSAPort = 9060;
			String host = "127.0.0.1";
			byte[] hash = SHA256(registerRequest.getDocument());
			TimestampResponse timeResponse = GetTimeStampResponse(TSAPort, host, hash);
			if (VerifyTSA(hash, timeResponse)) {

				String timestamp = timeResponse.getTimeStamp();
				/************* Verifican firma cliente *********************/
				boolean docVerified = serverSigner.VerifyClientSign(registerRequest.getDocument(),
						registerRequest.getDocSign());
				if (docVerified) {
					byte[] serverSign = GetMySign(id, registerRequest, timestamp);
					SaveFile(id, registerRequest, ownerId, docName, timeResponse, timestamp, serverSign);
				} else {
					// error verifying doc
					RegisterResponse response = new RegisterResponse(id, 0, null, null, false);
					sendObject.writeObject(response);
				}
			} else {
				// error verifying TSA
				RegisterResponse response = new RegisterResponse(id, 2, null, null, false);
				sendObject.writeObject(response);
			}
		} catch (IOException | ClassNotFoundException | UnrecoverableEntryException | NoSuchPaddingException
				| NoSuchAlgorithmException | CertificateException | InvalidKeyException | BadPaddingException
				| KeyStoreException | IllegalBlockSizeException | SignatureException e) {
			e.printStackTrace();
		}
	}

	private byte[] GetMySign(int id, RegisterRequest registerRequest, String timestamp) throws IOException {
		ByteArrayOutputStream writeSign = new ByteArrayOutputStream();
		DataOutputStream write = new DataOutputStream(writeSign);
		write.writeInt(id);
		write.writeUTF(timestamp);
		write.write(registerRequest.getDocument());
		write.write(registerRequest.getDocSign());

		byte[] sign = writeSign.toByteArray();
		writeSign.close();

		serverSigner.ServerSign(sign);
		byte[] serverSign = serverSigner.getServerSign();
		return serverSign;
	}

	private void SaveFile(int id, RegisterRequest registerRequest, String ownerId, String docName,
			TimestampResponse timeResponse, String timestamp, byte[] serverSign) throws KeyStoreException, IOException,
			CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidKeyException,
			NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, FileNotFoundException {
		File file;
		Document document;
		String extension = docName.split("\\.")[1];
		String name = String.valueOf(id) + "_" + ownerId + ".sig";
		if (registerRequest.isPrivate()) {
			name += ".cif";
			byte[] cypheredDoc = serverSigner.CypherDoc(registerRequest.getDocument(), cypherAlgorithm);
			document = new Document(id, docName, extension, ownerId, timestamp, timeResponse.getTSASign(), true,
					cypheredDoc, registerRequest.getDocSign(), serverSign, serverSigner.getEncoding());
			DataBase newRegister = new DataBase(id, docName, ownerId, timestamp, true);
			dataBase.add(newRegister);
			file = new File(name);
			System.out.println("File saved\nSending response...\n");
		} else {
			document = new Document(id, docName, extension, ownerId, timestamp, timeResponse.getTSASign(), false,
					registerRequest.getDocument(), registerRequest.getDocSign(), serverSign, null);
			DataBase newRegister = new DataBase(id, docName, ownerId, timestamp, false);
			dataBase.add(newRegister);
			file = new File(name);
			System.out.println("File saved\nSending response...\n");
		}

		ObjectOutputStream writer = new ObjectOutputStream(new FileOutputStream(file));
		writer.writeObject(document);
		writer.close();
		RegisterResponse response = new RegisterResponse(id, 1, document.getServerSign(), document.getTimestamp(),
				true);
		sendObject.writeObject(response);
	}

	private boolean VerifyTSA(byte[] hash, TimestampResponse timeResponse)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		/******************
		 * Verificacion de la firma del TSA
		 *******************/
		ByteArrayOutputStream writefirma = new ByteArrayOutputStream();
		DataOutputStream esc = new DataOutputStream(writefirma);
		esc.write(hash);
		esc.writeUTF(timeResponse.getTimeStamp());
		byte[] TSASign = writefirma.toByteArray();
		writefirma.close();
		return serverSigner.verifyTSASign(TSASign, timeResponse.getTSASign());
	}

	private TimestampResponse GetTimeStampResponse(int TSAPort, String host, byte[] hash)
			throws IOException, UnknownHostException, ClassNotFoundException {
		SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket SSLsocket = (SSLSocket) socketFactory.createSocket(host, TSAPort);
		System.out.println("Inicio del handshake con el TSA");
		SSLsocket.startHandshake();
		System.out.println("HANDSHAKE DONE!!!\n");
		ObjectOutputStream sendObjectTSA = new ObjectOutputStream(SSLsocket.getOutputStream());
		ObjectInputStream receivedObjectTSA = new ObjectInputStream(SSLsocket.getInputStream());
		TimestampRequest request = new TimestampRequest(hash);
		sendObjectTSA.writeObject(request);
		System.out.println("Peticion de timestamp enviada al TSA...");
		System.out.println("Esperando respuesta...");
		TimestampResponse timeResponse = (TimestampResponse) receivedObjectTSA.readObject();
		return timeResponse;
	}

	private static byte[] SHA256(byte[] doc) {
		byte[] hash = null;
		try {
			MessageDigest algorit = MessageDigest.getInstance("SHA-256");
			hash = algorit.digest(doc);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return hash;
	}

	private int FindDoc(String ownerId, int registerId) {
		int ret = -1;
		for (int i = 0; i < dataBase.size(); i++) {
			String idP = dataBase.get(i).getOwnerId();
			int idR = dataBase.get(i).getRegisterId();
			if (idP.equals(ownerId) && (idR == registerId)) {
				return i;
			}
		}
		return ret;
	}

	private void RetrieveDocument() {

		try {
			RetrieveRequest request = (RetrieveRequest) receivedObject.readObject();
			String ownerId = request.getOwnerId();
			int registerId = request.getRegisterId();

			System.out.println("RETRIEVING");
			System.out.println("IdRegistro:: " + registerId);
			System.out.println("Propietario:: " + ownerId);
			int i = FindDoc(ownerId, registerId);
			if (i >= 0) {
				if (dataBase.get(i).isPrivate()) { // privado
					PrivateDocumentResponse(request, ownerId, registerId);
				} else { // No privado
					PublicDocumentResponse(ownerId, registerId);
				}

			} else {
				// Doesn't exist document
				RetrieveResponse response = new RetrieveResponse(registerId, 1, null, null, null, null, null, "",
						false);
				System.out.println("Document doesn't exist " + registerId + " " + ownerId + "\n\n");
				sendObject.writeObject(response);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void PublicDocumentResponse(String ownerId, int registerId)
			throws IOException, FileNotFoundException, ClassNotFoundException {
		String ruta = String.valueOf(registerId) + "_" + ownerId + ".sig";
		ObjectInputStream leerObjeto = new ObjectInputStream(new FileInputStream(ruta));
		Document provisional = (Document) leerObjeto.readObject();
		leerObjeto.close();
		byte[] docRec = provisional.getDoc();
		RetrieveResponse respuesta = new RetrieveResponse(registerId, 0, provisional.getExtension(), docRec,
				provisional.getServerSign(), provisional.getClientSign(), provisional.getTSASign(),
				provisional.getTimestamp(), true);
		sendObject.writeObject(respuesta);
		System.out.println("\tRETRIEVED DOCUMENT\n\tSending response..\n");
	}

	private void PrivateDocumentResponse(RetrieveRequest request, String ownerId, int registerId)
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException,
			FileNotFoundException, ClassNotFoundException, Exception {
		/******* Validar firma cliente ****/
		ByteArrayOutputStream signWriter = new ByteArrayOutputStream();
		DataOutputStream writer = new DataOutputStream(signWriter);
		writer.writeUTF(ownerId);
		writer.writeInt(registerId);
		byte[] clientSign = signWriter.toByteArray();
		signWriter.close();
		if (!serverSigner.VerifyClientSign(clientSign, request.getClientSign())) {
			RetrieveResponse response = new RetrieveResponse(registerId, 2, null, null, null, null, null, "", false);
			sendObject.writeObject(response);
			System.out.println("Client sign is not valid \nSending response...\n");
		} else {
			String path = String.valueOf(registerId) + "_" + ownerId + ".sig.cif";
			ObjectInputStream objectStream = new ObjectInputStream(new FileInputStream(path));
			Document temp = (Document) objectStream.readObject();
			objectStream.close();
			byte[] decypheredDoc = serverSigner.DecypherDoc(temp.getDoc(), temp.getEncoding(), cypherAlgorithm);
			RetrieveResponse response = new RetrieveResponse(registerId, 0, temp.getExtension(), decypheredDoc,
					temp.getServerSign(), temp.getClientSign(), temp.getTSASign(), temp.getTimestamp(), true);
			sendObject.writeObject(response);
			System.out.println("\tRETRIEVED DOCUMENT\n\tSending response..\n");
		}
	}

	private void ListDocuments() {
		try {
			ListRequest request = (ListRequest) receivedObject.readObject();
			String ownerId = request.getOwnerId();

			System.out.println("LIST");
			System.out.println("Propietario:: " + ownerId);
			LinkedList<String> publicList = new LinkedList<>();
			LinkedList<String> privateList = new LinkedList<>();
			int registerId;
			String docName;
			String timestamp;
			for (DataBase register : dataBase) {
				if (register.isPrivate()) {
					if (register.getOwnerId().equalsIgnoreCase(ownerId)) {
						registerId = register.getRegisterId();
						docName = register.getDocName();
						timestamp = register.getTimestamp();
						privateList.add("IdRregistro: " + registerId + "| Nombre: " + docName + "| SelloTemporal: "
								+ timestamp);
					}
				} else {
					registerId = register.getRegisterId();
					docName = register.getDocName();
					timestamp = register.getTimestamp();
					publicList.add(
							"IdRregistro: " + registerId + "| Nombre: " + docName + "| SelloTemporal: " + timestamp);
				}
			}
			if (publicList.isEmpty()) {
				System.out.println("There are no public documents");
			}
			if (privateList.isEmpty()) {
				System.out.println("There are no private documents of: " + ownerId);
			}
			ListResponse response = new ListResponse(publicList, privateList);
			sendObject.writeObject(response);
			System.out.println("\n\tSending response...\n");

		} catch (ClassNotFoundException | IOException e) {
			e.printStackTrace();
		}
	}

	public int GetNewRegisterId() {
		int toRet = 1;
		while (registerIDs.contains(toRet)) {
			toRet++;
		}
		registerIDs.add(toRet);
		return toRet;
	}

	public static String GetKeyStorePath(String keyStore) {
		String toRet = "";
		String jce = ".jce";
		String root = System.getProperty("user.dir");
		Path commonPath = Paths.get(root, "keystores");
		Path tempPath = Paths.get(commonPath.toString(), keyStore + jce);
		toRet = tempPath.toString();
		return toRet;
	}

}
