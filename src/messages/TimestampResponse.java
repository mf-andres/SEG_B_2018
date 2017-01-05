package messages;

import java.io.Serializable;

public class TimestampResponse implements Serializable {

	private String selloTemporal;
	private byte[] firmaTSA;

	public TimestampResponse(String selloTemporal, byte[] firmaTSA) {
		this.selloTemporal = selloTemporal;
		this.firmaTSA = firmaTSA;
	}

	public String getTimeStamp() {
		return selloTemporal;
	}

	public byte[] getTSASign() {
		return firmaTSA;
	}
}
