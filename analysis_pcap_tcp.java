import org.jnetpcap.*;
import java.nio.*;
import java.util.ArrayList; 
class analysis_pcap_tcp{
	//  javac -classpath jnetpcap.jar analysis_pcap_tcp.java to compile using the imported library
	
	///     copy the jnetpcap.dll library file, found at root of jnetpcap's
    ///     installation directory to one of the window's system folders. This
    ///     could be \windows or \windows\system32 directory.
	
	public static void main(String[] args){
		String pcapFile = "assignment2.pcap";
		ArrayList<byte[]> packetsFromFile = readPacktsFromFile(pcapFile);
		System.out.println(packetsFromFile.size());
	}
	public static ArrayList<byte[]> readPacktsFromFile(String filePath) {
		final ArrayList<byte[]> packets = new ArrayList<byte[]>();
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(filePath, errbuf);
		ByteBufferHandler<String> handler = new ByteBufferHandler<String>() {
			public void nextPacket(PcapHeader arg0, ByteBuffer buffer, String arg2) {
				byte[] b = new byte[buffer.capacity()];
				buffer.get(b);
				packets.add(b);
			}
		};

		pcap.loop(Pcap.LOOP_INFINITE, handler, "");
		return packets;
	}
}