package messages;

import java.io.Serializable;
import java.util.LinkedList;

public class ListResponse implements Serializable {
	private LinkedList<String> ListaDocPublicos = new LinkedList<>();
	private LinkedList<String> ListaDocPrivados = new LinkedList<>();

	public ListResponse(LinkedList ListaDocPublicos, LinkedList ListaDocPrivados) {
		this.ListaDocPublicos = ListaDocPublicos;
		this.ListaDocPrivados = ListaDocPrivados;
	}

	public LinkedList<String> getListaDocPublicos() {
		return ListaDocPublicos;
	}

	public LinkedList<String> getListaDocPrivados() {
		return ListaDocPrivados;
	}
}
