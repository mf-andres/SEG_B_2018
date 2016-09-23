import java.util.Iterator;
import java.util.LinkedList;
import java.util.Scanner;
import java.io.*;

import javax.net.ssl.*;

public class Cliente {

 public static void main(String[] args) throws Exception {
	try {		

		definirKeyStores();
	    SSLSocketFactory factory =
	    		(SSLSocketFactory)SSLSocketFactory.getDefault();
	    System.out.println ("Crear socket");
	    SSLSocket socket =
	    		(SSLSocket)factory.createSocket(args[0], 9001);
	    
	    // Ver las suites SSL disponibles

	    System.out.println ("CypherSuites");
	    SSLContext context = SSLContext.getDefault();
	    SSLSocketFactory sf = context.getSocketFactory();
	    String[] cipherSuites = sf.getSupportedCipherSuites();
	    for (int i=0; i<cipherSuites.length; i++) 
	    		System.out.println (cipherSuites[i]);


	    // Protocolo SSL Handshake 
	    
	    System.out.println ("Comienzo SSL Handshake");
	    socket.startHandshake();	    
	    System.out.println ("Fin SSL Handshake");

	    Scanner keyboard = new Scanner(System.in);
	    String usuario;
	    int documento;
	    System.out.println("Introduzca usuario");
	    usuario=keyboard.next();

	    System.out.println("Pulse 1 si quiere registrar un documento, pulse otro si quiere pedir un documento");
		if(keyboard.nextInt()==1)
		   registrarDocumento(socket,usuario);
	   else {
		   System.out.println("Introduzca numero documento que ha recibido del servidor");
		    documento=keyboard.nextInt();
		   pedirDocumento(socket,documento,usuario);   
	   }
		keyboard.close();

	    socket.close();

	} catch (Exception e) {
	    e.printStackTrace();
	}
    }
 	static void pedirDocumento(SSLSocket socket,int documento,String usuario) throws IOException{
 		/***********************************
 		 * EMPIEZO LA PETICION
 		 * ***********************************
 		 * ************************************
 		 ***************************************/
	    PrintWriter out = new PrintWriter(
				  new BufferedWriter(
				  new OutputStreamWriter(
   				  socket.getOutputStream())));
	    out.println("GET " + "/" + documento  + " HTTP/1.0"); //envio el documento y el usuario
	    out.println("IdPropietario:"+usuario);
	    out.println();
	    out.flush();
	    /**********************************
	     * COMIENZO EL RECIBIR LOS MENSAJES
	     * **********************************
	     *************************************/
	    if (out.checkError())
			System.out.println("SSLSocketClient:  java.io.PrintWriter error");
	    BufferedReader in = new BufferedReader(
							    new InputStreamReader(
							    		socket.getInputStream()));

	    String inputLine;
	    LinkedList<String> datosRecepcion= new LinkedList<String>();
	    while ((inputLine = in.readLine()) != null){
	    	System.out.println(inputLine);
	    	datosRecepcion.add(inputLine);//hago esto para guardar los datos y luego comprobarlos
	    }
	    
	    /**************************
	     * COMIENZO LAS COMPROBACIONES
	     * **************************
	     *****************************/
	    Iterator<String> iterador = datosRecepcion.iterator();
	    String temp;
	    while(iterador.hasNext()){
	    	temp=iterador.next();
	    	if(temp.contains("Error:")){ //vamos a indicar desde el server si hay error o está bien como Error:X
	    		if(temp.contains("0")){
	    			errores(temp);
	    		}else{
	    	    	//aqui hay que verificar si la firma del registrador sobre el documento es correcta y lanzar mensaje de exito o fallo
	    	    	//junto el numero del registro y el sello temporal
	    		}
	    	}
	    }	
	    
	    in.close();
	    out.close();
 	}
 	static void errores(String numero){
 		int err= Integer.parseInt(numero);
 		switch(err){
 			//empiezo con 1 xq el 0 es para decir q está bien
 			case 1:
 				break;
 		}
 	}
 	static void registrarDocumento(SSLSocket socket,String usuario) throws IOException{
 		System.out.println("Introduzca el path del documento");
 		Scanner keyboard = new Scanner(System.in);
 		String documento= keyboard.next();
 		File archivo= new File(documento);
 		BufferedReader bf= new BufferedReader(new FileReader(archivo));
 		System.out.println("¿Es privado? (s/n)");
 		boolean privado;
 		if(keyboard.next().equals("s")){
 			privado=true;
 		}else
 			privado= false;
 		/**************************************************************
 		 * EMPIEZA EL ENVIO
 		 * **************************************************************
 		 *****************************************************************/
 	    PrintWriter out = new PrintWriter(
				  new BufferedWriter(
				  new OutputStreamWriter(
 				  socket.getOutputStream())));
	    out.println("Post " + "/" + documento  + " HTTP/1.0"); //con esto le digo lo que envio aunque le enviemos una path a el le dará igual ya que 
	    														//desde el servidor vamos a darle un numero de registro X y lo vamos a guardar como ese numero
	    out.println("IdPropietario:"+usuario);//con esto le digo el usuario
	    if(privado)//con esto le digo la confidencialidad
	    	out.println("Confidencialidad:Privado");
	    else
	    	out.println("Confidencialidad:Publico");
	    out.println();
	    String temp="";
	    while((temp=bf.readLine())!=null){ //con esto mando el documento
	    	out.println(temp);
	    }

	    /***************************************
	    *FALTA ENVIAR LA FIRMA
	    ******************************************
	    *******************************************
	    ********************************************
	    *********************************************/
	    out.flush();
	    /***************************************************
	     * TERMINA EL ENVIO
	     * AHORA VAMOS A COMPROBAR QUE NOS DICE EL SERVER
	     ******************************************************/
	    BufferedReader in = new BufferedReader(
			    new InputStreamReader(
			    		socket.getInputStream()));
	    String inputLine;
	    LinkedList<String> datosRecepcion= new LinkedList<String>();
	    while ((inputLine = in.readLine()) != null){
	    	System.out.println(inputLine);
	    	datosRecepcion.add(inputLine);//hago esto para guardar los datos y luego comprobarlos
	    }
	    Iterator<String> iterador = datosRecepcion.iterator();
	    while(iterador.hasNext()){
	    	temp=iterador.next();
	    	if(temp.contains("Error:")){ //vamos a indicar desde el server si hay error o está bien como Error:X
	    		if(temp.contains("0")){
	    			errores(temp);
	    		}else{
	    	    	//aqui hay que verificar si la firma del registrador sobre el documento es correcta y lanzar mensaje de exito o fallo
	    	    	//junto el numero del registro y el sello temporaly borrar el documento de este ordenador
	    		}
	    	}
	    }
	    /*************************************************
	     * TERMINA LA COMPROBACION
	     * Y CIERRO LAS COSAS
	     ***************************************************/
	    in.close();
	    bf.close();
	    keyboard.close();
 		
 	}
    /******************************************************
		definirKeyStores() no tengo mucha idea de esto así que lo dejé sin tocar XD
    *******************************************************/
	private static void definirKeyStores(){
		
		String 	raiz = "/" ;

		// Almacen de claves		
		
		System.setProperty("javax.net.ssl.keyStore",         raiz + "testkeys.jks");
		System.setProperty("javax.net.ssl.keyStoreType",     "JKS");
	    System.setProperty("javax.net.ssl.keyStorePassword", "passphrase");
	
	    // Almacen de confianza
	    
	    System.setProperty("javax.net.ssl.trustStore",          raiz + "samplecacerts.jks");
		System.setProperty("javax.net.ssl.trustStoreType",     "JKS");
	    System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
	}
}