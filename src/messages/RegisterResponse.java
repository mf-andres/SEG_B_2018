package messages;

import java.io.Serializable;

public class RegisterResponse implements Serializable {

	private long registerId;
	private int message;
	byte[] serverSign;
	private String timestamp;
	private boolean valid;

	public RegisterResponse(long registerId, int message, byte[] serverSign, String timestap,
			boolean valid) {
		this.registerId = registerId;
		this.timestamp = timestap;
		this.message = message;
		this.serverSign = serverSign;
		this.valid = valid;
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

	public byte[] getServerSign() {
		return serverSign;
	}

	public String getTimestamp() {
		return timestamp;
	}
}
