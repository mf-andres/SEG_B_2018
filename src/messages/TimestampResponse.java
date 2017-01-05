package messages;

import java.io.Serializable;

public class TimestampResponse implements Serializable {

	private String timestamp;
	private byte[] TSASign;

	public TimestampResponse(String timestamp, byte[] TSASign) {
		this.timestamp = timestamp;
		this.TSASign = TSASign;
	}

	public String getTimeStamp() {
		return timestamp;
	}

	public byte[] getTSASign() {
		return TSASign;
	}
}
