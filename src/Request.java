import java.io.Serializable;
import java.security.cert.X509Certificate;

public class Request implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -6172002794652759546L;
	
	int type;
	String docName;
	String confType;
	byte[] cipheredDoc;
	byte[] signedDoc;
	X509Certificate signCert;
	X509Certificate authCert;
	int rid;
	
	public Request(String docName, String confType, byte[] cipheredDoc, byte[] signedDoc, X509Certificate mySignCert) {
	
		this.docName = docName;
		this.confType = confType;
		this.cipheredDoc = cipheredDoc;
		this.signedDoc = signedDoc;
		this.signCert = mySignCert;
	}
	
	public Request(String confType, X509Certificate authCert) {
		
		this.confType = confType;
		this.authCert = authCert;
	}

	public Request(X509Certificate authCert, int rid) {

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
	public byte[] getCipheredDoc() {
		return cipheredDoc;
	}
	public void setCipheredDoc(byte[] cipheredDoc) {
		this.cipheredDoc = cipheredDoc;
	}
	public byte[] getSignedDoc() {
		return signedDoc;
	}
	public void setSignedDoc(byte[] signDoc) {
		this.signedDoc = signDoc;
	}
	public X509Certificate getSignCert() {
		return signCert;
	}
	public void setSignCert(X509Certificate signCert) {
		this.signCert = signCert;
	}
	public X509Certificate getAuthCert() {
		return authCert;
	}
	public void setAuthCert(X509Certificate authCert) {
		this.authCert = authCert;
	}
	public int getRID() {
		return rid;
	}
	public void setRID(int rID) {
		rid = rID;
	}
}
