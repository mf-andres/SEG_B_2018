package messages;

import java.io.Serializable;

public class TimestampRequest implements Serializable {

	private byte[] hashDoc;

	public TimestampRequest(byte[] hashDoc) {
		this.hashDoc = hashDoc;
	}

	public byte[] getHashDoc() {
		return hashDoc;
	}
}
