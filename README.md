# SEG_B_2018
Client and server aplications that interchange documents via a secured ssl/tls channel

Client arguments:
keyStoreFile trustStoreFile

Client arguments example:
ClientKeyStore.jce ClientTrustStore.jce

Server arguments:
keyStoreFile KeyStorePassword trustStoreFile cipheringAlgorithm

Server arguments example:
ServerKeyStore.jce 123456 ServerTrustStore.jce AES