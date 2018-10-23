
public class Server {

	KeyStore keyStore;
	TrustStore trustStore;
	char[] passphrase;
	int port;
	
	public static void main(String[] args) {

		getArgs(args);
		
		while(true) {
			
			waitForConection();
			
			int request  = getRequest();
			
			switch (request) {
			case 1:
				
				registerDocResponse();
				break;
				
			case 2:
				
				listDocsResponse();
				break;
				
			case 3:
				
				recoverDocResponse();
				break;

			default:
				
				System.out.println("Something went odd");
				System.out.println("Goodbye");
				return;
			}
		}
	}

}
