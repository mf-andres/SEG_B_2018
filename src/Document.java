import java.io.Serializable;

public class Document implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 3424675312007725098L;
	
	String name;
	byte[] content;
	String confType;
	String TimeStamp;
	
	byte[] documentBytes;
	byte[] serverSignature;
	int rID;
	byte[] signedDoc;
	String clientID;
	
	public Document(byte[] documentBytes, byte[] serverSignature, int rID, String timeStamp, byte[] signedDoc, String confType, String clientID) {

		this.documentBytes = documentBytes;
		this.serverSignature = serverSignature; 
		this.rID = rID;
		this.TimeStamp = timeStamp;
		this.signedDoc = signedDoc;
		this.confType = confType;
		this.clientID = clientID;
	}

	public Document() {
	}

	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}

	public byte[] getContent() {
		return content;
	}

	public void setContent(byte[] content) {
		this.content = content;
	}
	
	public String getConfType() {
		return confType;
	}
	
	public void setConfType(String confType) {
		this.confType = confType;
	}
	
	public String getTimeStamp() {
		return TimeStamp;
	}
	
	public void setTimeStamp(String timeStamp) {
		TimeStamp = timeStamp;
	}

	public byte[] getDocumentBytes() {
		return documentBytes;
	}

	public void setDocumentBytes(byte[] documentBytes) {
		this.documentBytes = documentBytes;
	}

	public byte[] getServerSignature() {
		return serverSignature;
	}

	public void setServerSignature(byte[] docSignature) {
		this.serverSignature = docSignature;
	}

	public int getrID() {
		return rID;
	}

	public void setrID(int rID) {
		this.rID = rID;
	}

	public byte[] getSignedDoc() {
		return signedDoc;
	}

	public void setSignedDoc(byte[] signedDoc) {
		this.signedDoc = signedDoc;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public String getClientID() {
		return clientID;
	}

	public void setClientID(String clientID) {
		this.clientID = clientID;
	}
}
