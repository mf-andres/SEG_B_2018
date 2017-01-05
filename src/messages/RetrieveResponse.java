package messages;

import java.io.Serializable;

public class RetrieveResponse implements Serializable {

	private long registerId;
	private int message;
	byte[] serverSign;
	private byte[] doc;
	private String extension;
	private String timestamp;
	private boolean valid;
	private byte[] clientSign;
	private byte[] TSASign;

	public RetrieveResponse(long registerId, int message, String extension, byte[] doc, byte[] serverSign,
			byte[] clientSign, byte[] TSASign, String timestamp, boolean valid) {
		this.registerId = registerId;
		this.timestamp = timestamp;
		this.doc = doc;
		this.extension = extension;
		this.message = message;
		this.clientSign = clientSign;
		this.serverSign = serverSign;
		this.valid = valid;
		this.TSASign = TSASign;

	}

	public byte[] getServerSign() {
		return serverSign;
	}

	public byte[] getClientSign() {
		return clientSign;
	}

	public byte[] getTSASign() {
		return TSASign;
	}

	public String getExtension() {
		return extension;
	}

	public byte[] getDoc() {
		return doc;
	}

	public long getRegisterId() {
		return registerId;
	}

	public int getMessage() {
		return message;
	}

	public boolean isValid() {
		return valid;
	}

	public String getTimestamp() {
		return timestamp;
	}
}
