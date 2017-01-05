package messages;

import java.io.Serializable;

public class RetrieveRequest implements Serializable {

	private String ownerId;
	private int registerId;
	byte[] clientSign;

	public RetrieveRequest(String ownerId, int registerId, byte[] clientSign) {
		this.ownerId = ownerId;
		this.registerId = registerId;
		this.clientSign = clientSign;
	}

	public int getRegisterId() {
		return registerId;
	}

	public String getOwnerId() {
		return ownerId;
	}

	public byte[] getClientSign() {
		return clientSign;
	}
}
