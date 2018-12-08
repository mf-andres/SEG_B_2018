import java.io.Serializable;

public class Request implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6172002794652759546L;
	
	int type;
	String docName;
	String confType;
	byte[] cypheredDoc;
	byte[] signedDoc;
	byte[] signCert;
	byte[] authCert;
	int rid;
	
	public Request(String docName, String confType, byte[] cypheredDoc, byte[] signedDoc) {
	
		this.docName = docName;
		this.confType = confType;
		this.cypheredDoc = cypheredDoc;
		this.signedDoc = signedDoc;
	}
	
	public Request(String confType, byte[] authCert) {
		
		this.confType = confType;
		this.authCert = authCert;
	}

	public Request(byte[] authCert, int rid) {

		this.authCert = authCert;
		this.rid = rid;
	}

	public int getType() {
		return type;
	}
	public void setType(int type) {
		this.type = type;
	}
	public String getDocName() {
		return docName;
	}
	public void setDocName(String docName) {
		this.docName = docName;
	}
	public String getConfType() {
		return confType;
	}
	public void setConfType(String confType) {
		this.confType = confType;
	}
	public byte[] getCypheredDoc() {
		return cypheredDoc;
	}
	public void setCypheredDoc(byte[] cypheredDoc) {
		this.cypheredDoc = cypheredDoc;
	}
	public byte[] getSignedDoc() {
		return signedDoc;
	}
	public void setSignedDoc(byte[] signDoc) {
		this.signedDoc = signDoc;
	}
	public byte[] getSignCert() {
		return signCert;
	}
	public void setSignCert(byte[] signCert) {
		this.signCert = signCert;
	}
	public byte[] getAuthCert() {
		return authCert;
	}
	public void setAuthCert(byte[] authCert) {
		this.authCert = authCert;
	}
	public int getRID() {
		return rid;
	}
	public void setRID(int rID) {
		rid = rID;
	}
}
