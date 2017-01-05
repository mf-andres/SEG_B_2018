package client;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Scanner;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import messages.ListRequest;
import messages.ListResponse;
import messages.RegisterRequest;
import messages.RegisterResponse;
import messages.RetrieveRequest;
import messages.RetrieveResponse;

public class Client {

	static PrintWriter sendData;
	static ClientSignVerifier signer;
	private static ObjectInputStream receivedObject;
	private static ObjectOutputStream sendObject;
	private static Scanner command;
	private static SSLSocket socket;

	public static void main(String[] args) throws NoSuchAlgorithmException {

		int port = 11233;
		String host = "127.0.0.1";
		command = new Scanner(System.in);
		SetKeystores(args);

		try {
			SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			/************** SSL SUITES *******************/
			String[] suites = socketFactory.getSupportedCipherSuites();
			int selected = GetSSLSuite(suites);
			Connection(port, host, socketFactory, suites, selected);

		} catch (IOException e) {
			System.out.println("ERROR!!! en HandShake, Cipher o Contraseñas!!! ::" + e.getMessage());
			return;
		}
		MainMenu();
	}

	private static int GetSSLSuite(String[] suites) {
		int toRet = -1;
		System.out.println("!!SSL SUITES!!");
		for (int i = 0; i < suites.length; i++) {
			System.out.println(i + 1 + ".- " + suites[i]);
		}

		System.out.println("\nIntroduzca número de suite:\n");
		while (toRet == -1) {
			String temp = command.nextLine();
			if (temp.equals("")) {
				continue;
			}
			toRet = Integer.parseInt(temp);
			if (toRet < 0 || toRet > suites.length) {
				System.out.println("Introduzca un numero válido");
				toRet = -1;
			}
		}
		System.out.println("Suite escogida");
		return toRet;
	}

	private static void Connection(int port, String host, SSLSocketFactory socketFactory, String[] suites, int selected)
			throws IOException, UnknownHostException {
		socket = (SSLSocket) socketFactory.createSocket(host, port);
		String[] enabledCiphers = new String[1];
		enabledCiphers[0] = suites[selected];
		socket.setEnabledCipherSuites(enabledCiphers);
		socket.startHandshake();
		System.out.println("HandShake established!!!");
		// Retrieve communication channels
		CommunicationChannels(socket);
	}

	private static void CommunicationChannels(SSLSocket SSLsocket) throws IOException {
		sendData = new PrintWriter(new BufferedWriter(new OutputStreamWriter(SSLsocket.getOutputStream())), true);
		String keyStorePath = GetKeyStorePath("clientKeyStore");
		String trustStorePath = GetKeyStorePath("clientTrustStore");
		signer = new ClientSignVerifier(keyStorePath, trustStorePath);
		sendObject = new ObjectOutputStream(SSLsocket.getOutputStream());
		receivedObject = new ObjectInputStream(SSLsocket.getInputStream());
	}

	public static void MainMenu() {
		boolean exit = false;
		// commands in a file
		File exe = new File("exe.txt");
		String temp;
		Scanner executer = null;
		try {
			executer = new Scanner(exe);

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			try {
				socket.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			System.exit(0);
		}
		while (!exit) {

			System.out.println("READING NEXT COMMAND\n\n");
			temp = executer.nextLine();

			String command[] = temp.split(" ");

			switch (command[0]) {
			case "REGISTRAR_DOCUMENTO":
				System.out.println("REGISTER DOCUMENT");
				RegisterDocument(command);
				break;
			case "RECUPERAR_DOCUMENTO":
				System.out.println("RETRIEVE DOCUMENT");
				RetrieveDocument(command);
				break;
			case "LISTAR_DOCUMENTOS":
				System.out.println("LIST DOCUMENTS");
				ListDocuments(command);
				break;
			case "EXIT":
				System.out.println("EXIT");
				exit = true;
				break;
			default:
				System.out.println("COMMAND ERROR");
				break;
			}
		}

	}

	private static void RegisterDocument(String[] command) {

		if (command.length != 4) {
			System.out.println("SYNTAX ERROR!! ej: ");
			System.out.println("REGISTRAR_DOCUMENTO idPropietario nombreDocumento tipoConfidencialidad");
			return;
		}
		String ownerId = command[1];
		String docName = command[2];
		String confidenciality = command[3];
		sendData.println("1");
		String debug = "OwnerID: " + ownerId + "\nDocumento: " + docName + "\nConfidencialidad: " + confidenciality;
		System.out.println(debug);

		try {
			System.out.println("Reading: " + docName);
			String root = System.getProperty("user.dir");
			Path path = Paths.get(root, docName);
			File doc = new File(path.toString());
			int size = (int) doc.length();
			DataInputStream leer = new DataInputStream(new FileInputStream(doc));
			byte[] documento = new byte[size];
			leer.readFully(documento);
			leer.close();
			System.out.println("Doc read");
			signer.FirmarDocumento(documento);
			boolean bPrivate = confidenciality.equalsIgnoreCase("privado") ? true : false;
			RegisterRequest peticion = new RegisterRequest(docName, ownerId, documento, signer.getFirma(), bPrivate);
			sendObject.writeObject(peticion);
			System.out.println("Register petition sent, waiting....");
			RegisterResponse respuesta = (RegisterResponse) receivedObject.readObject();
			if (respuesta.isCorrecto()) {
				// only delete file if it was correct
				doc.delete();
				System.out.println("Documento correctamente registrado");
				debug = "IdRegistro: " + respuesta.getIdRegistro() + "\nTimeStamp: " + respuesta.getSelloTemporal();
				debug += "\nFirma del servidor: " + respuesta.getFirmaServidor().toString();
				System.out.println(debug);
				// HASH
				String hashD = "hash_" + String.valueOf(respuesta.getIdRegistro()) + ownerId + ".txt";
				byte[] hashDoc = SHA256(documento);
				Files.write(Paths.get(hashD), hashDoc);
			} else {
				int error = respuesta.getMensaje();
				String mensaje;
				switch (error) {
				case 1:
					mensaje = "Verificación de la firma del documento del cliente en el servidor no valida";
					break;
				case 2:
					mensaje = "Fallo de firma de TimeStamp";
					break;
				default:
					mensaje = "Error desconocido";
					break;
				}
				System.out.println("ERROR: " + mensaje + "\n\n");
			}

		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}

	}

	private static void RetrieveDocument(String[] command) {

		if (command.length != 3) {
			System.out.println("SYNTAX ERROR!! ej: ");
			System.out.println("RECUPERAR_DOCUMENTO idPropietario idRegistro");
			return;
		}
		String idPropietario = command[1];
		int idRegistro = Integer.parseInt(command[2]);

		sendData.println("2");
		sendData.flush();

		ByteArrayOutputStream firma = new ByteArrayOutputStream();
		DataOutputStream add = new DataOutputStream(firma);
		try {
			/***************** Crear firma **************/
			add.writeUTF(idPropietario);
			add.writeInt(idRegistro);
			byte[] firmaCliente = firma.toByteArray();
			firma.close();
			String keyStorePath = GetKeyStorePath("clientKeyStore");
			String trustStorePath = GetKeyStorePath("clientTrustStore");
			ClientSignVerifier firmarcliente = new ClientSignVerifier(keyStorePath, trustStorePath);
			firmarcliente.FirmarDocumento(firmaCliente);
			RetrieveRequest peticion = new RetrieveRequest(idPropietario, idRegistro, firmarcliente.getFirma());
			sendObject.writeObject(peticion);
			System.out.println("Retrieve petition sent, waiting....");
			RetrieveResponse respuesta = (RetrieveResponse) receivedObject.readObject();
			/******************
			 * Comprobar respuesta del servidor
			 **********************/
			if (respuesta.isCorrecto()) {
				/********************
				 * VALIDAR FIRMA TSA
				 ******************************/
				ByteArrayOutputStream writefirma = new ByteArrayOutputStream();
				DataOutputStream esc = new DataOutputStream(writefirma);
				esc.write(SHA256(respuesta.getDoc()));
				esc.writeUTF(respuesta.getSelloTemporal());
				byte[] firmaTSA = writefirma.toByteArray();
				writefirma.close();
				boolean validoTSA = firmarcliente.verificarFirmaTSA(firmaTSA, respuesta.getFirmaTSA());
				if (validoTSA) {
					/******* Validar firma servidor ****/
					ByteArrayOutputStream escribirfirma = new ByteArrayOutputStream();
					DataOutputStream escribir = new DataOutputStream(escribirfirma);
					escribir.writeInt(idRegistro);
					escribir.writeUTF(respuesta.getSelloTemporal());
					escribir.write(respuesta.getDoc());
					escribir.write(respuesta.getFirmaCliente());

					byte[] sigServ = escribirfirma.toByteArray();
					escribirfirma.close();
					boolean valida = firmarcliente.verificarServidor(sigServ, respuesta.getFirmaServidor());
					if (valida) {
						/******* Firma servidor validada ****/

						File recuperado = new File(
								"recuperado_" + respuesta.getIdRegistro() + "." + respuesta.getExtension());
						DataOutputStream nuevofichero = new DataOutputStream(new FileOutputStream(recuperado));
						nuevofichero.write(respuesta.getDoc());
						nuevofichero.close();

						String concat = String.valueOf(idRegistro) + idPropietario;
						boolean ficherosIguales = ficherosIguales(respuesta.getDoc(), concat);
						/*********************
						 * Comprobar hash del documento almacenado y del
						 * recuperado
						 *************************/
						if (ficherosIguales) {
							System.out.println("Documento recuperado correctamente");
							System.out.println("IdRegistro: " + respuesta.getIdRegistro());
							System.out.println("Sello temporal: " + respuesta.getSelloTemporal());
							System.out.println("Firma del servidor: " + respuesta.getFirmaServidor().toString());
						} else {
							System.out.println("Documento alterado por el registrador");
						}
						// Ya se imprime el error en la funcion de validar
					}
				}
			} else {
				int error = respuesta.getMensaje();
				String mensaje;
				switch (error) {
				case 1:
					mensaje = "Documento no existente";
					break;
				case 2:
					mensaje = "Acceso no permitido";
					break;
				default:
					mensaje = "Error desconocido";
					break;
				}
				System.out.println("ERROR: " + mensaje + "\n\n");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static boolean ficherosIguales(byte[] docRecuperado, String concat) {
		String hash = "hash_" + concat + ".txt";
		byte[] hashDoc = null;
		try {
			hashDoc = Files.readAllBytes(Paths.get(hash));
		} catch (IOException e) {
			System.out.println("No se ha encontrado el hash en el sistema");
		}

		byte[] hashDocRec = SHA256(docRecuperado);
		if (hashDoc.length != hashDocRec.length) {
			System.out.println("Hash de diferentes tamaños");
			return false;
		}
		if (Arrays.equals(hashDoc, hashDocRec)) {
			return true;
		} else {
			return false;
		}
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

	private static void ListDocuments(String[] orden) {

		if (orden.length != 2) {
			System.out.println("Error de sintaxis. Faltan parametros.\n RECUPERAR_DOCUMENTO idPropietario idRegistro");
			return;
		}
		String idPropietario = orden[1];
		sendData.println("3");
		sendData.flush();

		ListRequest peticion = new ListRequest(idPropietario);
		try {
			sendObject.writeObject(peticion);
			System.out.println("Peticion para recuperar enviada...");
			System.out.println("Respuesta del servidor...\n");
			ListResponse respuesta = (ListResponse) receivedObject.readObject();
			LinkedList<String> ListaPublicos = respuesta.getListaDocPublicos();
			LinkedList<String> ListaPrivados = respuesta.getListaDocPrivados();

			System.out.println("Documentos publicos:");
			if (ListaPublicos.isEmpty()) {
				System.out.println("\tNo hay documentos publicos");
			} else {
				for (String doc : ListaPublicos) {
					System.out.println("\t- " + doc);
				}
			}
			System.out.println("Documentos privados:");
			if (ListaPrivados.isEmpty()) {
				System.out.println("\tNo hay documentos privados del propietario:" + idPropietario);
			} else {
				for (String doc : ListaPrivados) {
					System.out.println("\t- " + doc);
				}
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
		}

	}

	public static void SetKeystores(String[] args) {
		String keyStore = args[0];
		String trustStore = args[2];
		String passwKS = args[1];
		String passwTS = args[3];
		String pathKeyStore = GetKeyStorePath(keyStore);
		String pathTrustStore = GetKeyStorePath(trustStore);

		// Store formats
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		// Server KeyStore path
		System.setProperty("javax.net.ssl.keyStore", pathKeyStore);
		// Server KeyStore Password
		System.setProperty("javax.net.ssl.keyStorePassword", passwKS);
		// Server TrustStore path
		System.setProperty("javax.net.ssl.trustStore", pathTrustStore);
		// Server TrustStore Password
		System.setProperty("javax.net.ssl.trustStorePassword", passwTS);
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
