package messages;

import java.io.Serializable;
import java.util.LinkedList;

public class ListResponse implements Serializable {
	private LinkedList<String> publicList = new LinkedList<>();
	private LinkedList<String> privateList = new LinkedList<>();

	public ListResponse(LinkedList publicList, LinkedList privateList) {
		this.publicList = publicList;
		this.privateList = privateList;
	}

	public LinkedList<String> getPublicList() {
		return publicList;
	}

	public LinkedList<String> getPrivateList() {
		return privateList;
	}
}
