package messages;

import java.io.Serializable;

public class RegisterRequest implements Serializable {

	private String docName;
	private String ownerId;
	private byte[] doc;
	private byte[] docSign;
	private boolean bPrivate;

	public RegisterRequest(String docName, String ownerId, byte[] document, byte[] docSign,
			boolean privado) {
		this.docName = docName;
		this.ownerId = ownerId;
		this.doc = document;
		this.docSign = docSign;
		this.bPrivate = privado;
	}

	public String getDocName() {
		return docName;
	}

	public String getOwnerId() {
		return ownerId;
	}

	public byte[] getDocument() {
		return doc;
	}

	public byte[] getDocSign() {
		return docSign;
	}

	public boolean isPrivate() {
		return bPrivate;
	}
}
