package server;

public class DataBase {

	private int idRegistro;
	private String nombredoc;
	private String idPropietario;
	private String selloTemporal;
	private boolean privado;

	public DataBase(int idRegistro, String nombredoc, String idPropietario, String selloTemporal, boolean privado) {
		this.idRegistro = idRegistro;
		this.nombredoc = nombredoc;
		this.idPropietario = idPropietario;
		this.selloTemporal = selloTemporal;
		this.privado = privado;
	}

	public int getRegisterId() {
		return idRegistro;
	}

	public String getOwnerId() {
		return idPropietario;
	}

	public String getDocName() {
		return nombredoc;
	}

	public String getTimestamp() {
		return selloTemporal;
	}

	public boolean isPrivate() {
		return privado;
	}

}
