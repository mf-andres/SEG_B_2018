public byte[] CypherDoc(byte[] doc, String cypherAlgorithm) throws KeyStoreException, IOException,
			CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException, InvalidKeyException,
			NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

		KeyStore keyStores;
		char[] pass = "123456".toCharArray();
		char[] passKey = "123456".toCharArray();
		String algorithm;

		keyStores = KeyStore.getInstance("JCEKS");
		keyStores.load(new FileInputStream(pathToKeyStore), passKey);
		KeyStore.SecretKeyEntry ksEntry;
		if (cypherAlgorithm.equalsIgnoreCase("AES-128")) {
			ksEntry = (KeyStore.SecretKeyEntry) keyStores.getEntry("seckeyaes-128",
					new KeyStore.PasswordProtection(pass));
			algorithm = "AES/CBC/PKCS5Padding";
		} else {
			ksEntry = (KeyStore.SecretKeyEntry) keyStores.getEntry("seckeyarcfour",
					new KeyStore.PasswordProtection(pass));
			algorithm = "ARCFOUR";
		}
		SecretKey secretKey = ksEntry.getSecretKey();

		String provider = "SunJCE";
		byte cleanBlock[] = new byte[2024];
		byte cypheredBlock[];
		int blockSize;

		ByteArrayInputStream cleanDoc = new ByteArrayInputStream(doc);
		ByteArrayOutputStream cypheredDoc = new ByteArrayOutputStream();

		System.out.println("Starting doc cypher");
		Cipher cypher = Cipher.getInstance(algorithm);
		cypher.init(Cipher.ENCRYPT_MODE, secretKey);

		while ((blockSize = cleanDoc.read(cleanBlock)) > 0) {
			cypheredBlock = cypher.update(cleanBlock, 0, blockSize);
			cypheredDoc.write(cypheredBlock);
		}
		cypheredBlock = cypher.doFinal();
		cypheredDoc.write(cypheredBlock);
		System.out.println("\tCyphered alg: " + cypherAlgorithm + " Proveider: " + provider);
		cypheredDoc.close();
		cleanDoc.close();
		if (cypherAlgorithm.equals("AES-128")) {
			encoding = cypher.getParameters().getEncoded();
		}
		byte[] cypheredDocByte = cypheredDoc.toByteArray();
		return cypheredDocByte;
}
