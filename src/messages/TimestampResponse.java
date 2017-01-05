package messages;

import java.io.Serializable;

public class TimestampResponse implements Serializable {

	private String selloTemporal;
	private byte[] firmaTSA;

	public TimestampResponse(String selloTemporal, byte[] firmaTSA) {
		this.selloTemporal = selloTemporal;
		this.firmaTSA = firmaTSA;
	}

	public String getSelloTemporal() {
		return selloTemporal;
	}

	public byte[] getFirmaTSA() {
		return firmaTSA;
	}
}
