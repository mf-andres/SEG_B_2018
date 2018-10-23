import java.net.InetAddress;
import java.security.KeyStore;

public class Client {
	
	String keyStoreName;
	KeyStore keyStore;
	String trustStoreName;
	KeyStore trustStore;
	char[] passphrase;
	InetAddress host;
	int port;
	
	public static void main(String[] args) {

		getArgs(args);
		
		while(true) {
			
			int action = getAction();
			
			switch (action) {
			case 1:

				registerDoc();
				break;

			case 2:
				
				listDocs();
				break;
			case 3:
				
				recoverDoc();
				break;
				
			case 4:
				
				System.out.println("Exiting");
				System.out.println("Goodbye");
				return;
				
			default:

				System.out.println("Something went odd");
				System.out.println("Goodbye");
			}
		}
	}

}
