import org.jnetpcap.*;

class analysis_pcap_tcp{
	//  javac -classpath jnetpcap.jar analysis_pcap_tcp.java to compile using the imported library
	
	///     copy the jnetpcap.dll library file, found at root of jnetpcap's
    ///     installation directory to one of the window's system folders. This
    ///     could be \windows or \windows\system32 directory.
	
	public static void main(String[] args){
		StringBuilder errbuf = new StringBuilder();
		String pcapFile = "assignment2.pcap";
		Pcap pcap = Pcap.openOffline(pcapFile, errbuf);
	
		System.out.println(pcap.toString());

	}

}