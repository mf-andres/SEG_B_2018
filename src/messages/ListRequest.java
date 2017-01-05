package messages;

import java.io.Serializable;

public class ListRequest implements Serializable {
	private String idPropietario;

	public ListRequest(String idPropietario) {
		this.idPropietario = idPropietario;
	}

	public String getOwnerId() {
		return idPropietario;
	}
}
