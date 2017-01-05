package messages;

import java.io.Serializable;

public class RegisterRequest implements Serializable {

	private String nombreDoc;
	private String idPropietario;
	private byte[] documento;
	private byte[] firmaDoc;
	private boolean privado;

	public RegisterRequest(String nombreDoc, String idPropietario, byte[] documento, byte[] firmaDoc,
			boolean privado) {
		this.nombreDoc = nombreDoc;
		this.idPropietario = idPropietario;
		this.documento = documento;
		this.firmaDoc = firmaDoc;
		this.privado = privado;
	}

	public String getDocName() {
		return nombreDoc;
	}

	public String getOwnerId() {
		return idPropietario;
	}

	public byte[] getDocument() {
		return documento;
	}

	public byte[] getDocSign() {
		return firmaDoc;
	}

	public boolean isPrivate() {
		return privado;
	}
}
