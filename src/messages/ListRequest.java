package messages;

import java.io.Serializable;

public class ListRequest implements Serializable {
	private String ownerId;

	public ListRequest(String ownerId) {
		this.ownerId = ownerId;
	}

	public String getOwnerId() {
		return ownerId;
	}
}
