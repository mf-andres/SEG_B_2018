package messages;

import java.io.Serializable;

public class RetrieveRequest implements Serializable {

	private String idPropietario;
	private int idRegistro;
	byte[] firmaCliente;

	public RetrieveRequest(String idPropietario, int idRegistro, byte[] firmaCliente) {
		this.idPropietario = idPropietario;
		this.idRegistro = idRegistro;
		this.firmaCliente = firmaCliente;
	}

	public int getIdRegistro() {
		return idRegistro;
	}

	public String getIdPropietario() {
		return idPropietario;
	}

	public byte[] getFirmaCliente() {
		return firmaCliente;
	}
}
