import java.io.Serializable;

public class Response implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 969327944693952639L;
	
	byte[] signCert;
	int rid;
	String timeStamp;
	byte[] serverSignature;
	String confType;
	byte[] signedDoc;
	byte[] serverSignCert;
	byte[] cypheredDoc;
	byte[] authCert;
	
	public Response(int rid, String timeStamp, byte[] serverSignature, byte[] authCert) {
		
		this.rid = rid;
		this.timeStamp = timeStamp;
		this.serverSignature = serverSignature;
		this.authCert = authCert;
	}
	
	public Response(String confType, int rid, String timeStamp, byte[] cypheredDoc, byte[] serverSignature) {
		
		this.confType = confType;
		this.rid = rid;
		this.timeStamp = timeStamp;
		this.cypheredDoc = cypheredDoc;
		this.serverSignature = serverSignature;
	}
	
	public byte[] getSignCert() {
		return signCert;
	}
	public void setSignCert(byte[] signCert) {
		this.signCert = signCert;
	}
	public int getRID() {
		return rid;
	}
	public void setRID(int rID) {
		rid = rID;
	}
	public String getTimeStamp() {
		return timeStamp;
	}
	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}
	public byte[] getServerSignature() {
		return serverSignature;
	}
	public void setServerSignature(byte[] serverSignature) {
		this.serverSignature = serverSignature;
	}
	public String getConfType() {
		return confType;
	}
	public void setConfType(String confType) {
		this.confType = confType;
	}
	public byte[] getSignedDoc() {
		return signedDoc;
	}
	public void setSignedDoc(byte[] signedDoc) {
		this.signedDoc = signedDoc;
	}
	public byte[] getServerSignCert() {
		return serverSignCert;
	}
	public void setServerSignCert(byte[] serverSignCert) {
		this.serverSignCert = serverSignCert;
	}
	public byte[] getCypheredDoc() {
		return cypheredDoc;
	}
	public void setCypheredDoc(byte[] cypheredDoc) {
		this.cypheredDoc = cypheredDoc;
	}
}
