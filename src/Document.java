
public class Document {

	String name;
	byte[] content;
	String confType;
	String TimeStamp;
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}

	public byte[] getContent() {
		return content;
	}

	public void setContent(byte[] content) {
		this.content = content;
	}
	
	public String getConfType() {
		return confType;
	}
	
	public void setConfType(String confType) {
		this.confType = confType;
	}
	
	public String getTimeStamp() {
		return TimeStamp;
	}
	
	public void setTimeStamp(String timeStamp) {
		TimeStamp = timeStamp;
	}
}
