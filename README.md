# SEG_B_2018
This project was carried out for the Security subject of the Telecomunications Engineering Degree of the University of Vigo. 

The aim of the project was to develop a client and a server that could interchange documents via a secured ssl/tls channel.

Client arguments:
keyStoreFile trustStoreFile

Client arguments example:
ClientKeyStore.jce ClientTrustStore.jce

Server arguments:
keyStoreFile KeyStorePassword trustStoreFile cipheringAlgorithm

Server arguments example:
ServerKeyStore.jce 123456 ServerTrustStore.jce AES
