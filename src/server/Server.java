package server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class Server {
	static String algCifrado = "AES-128";

	public static void main(String[] args) {

		int port = 11233;
		SetKeystore(args);
		SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		try {

			/***********************/
			ServerSocket serverSocket = serverSocketFactory.createServerSocket(port);
			System.out.println("\nSERVER LAUNCHED!!\n");
			((SSLServerSocket) serverSocket).setNeedClientAuth(true);

			try {
				while (true) {
					Socket cliente = serverSocket.accept();
					ServerConnection serverConnection = new ServerConnection(cliente, algCifrado);
					serverConnection.start();
				}
			} catch (IOException e) {
				System.out.println("SERVER DOWN!!!! ERROR::" + e.getMessage());
				return;
			}

		} catch (IOException e) {
			System.out.println("\n ERROR CREATING SERVER SOCKETS!!! ::" + e.getMessage());
		}
	}

	private static void SetKeystore(String[] args) {
		String keyStore = args[0];
		String trustStore = args[2];
		String passwKS = args[1];
		String passwTS = args[3];
		String root = System.getProperty("user.dir");
		Path commonPath = Paths.get(root, "keystores");
		String jce = ".jce";
		Path tempPath = Paths.get(commonPath.toString(), keyStore + jce);
		String pathKeyStore = tempPath.toString();
		tempPath = Paths.get(commonPath.toString(), trustStore + jce);
		String pathTrustStore = tempPath.toString();

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
}
