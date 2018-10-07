import org.jnetpcap.*;
import java.nio.*;
import java.util.ArrayList; 
import java.util.Arrays;
import java.io.*;
import org.jnetpcap.protocol.tcpip.Tcp;
import java.math.BigInteger;
class analysis_pcap_tcp{
	static int initCount = 0;
	static int numFlows = 0;
	//  javac -classpath jnetpcap.jar analysis_pcap_tcp.java to compile using the imported library
	
	///     copy the jnetpcap.dll library file, found at root of jnetpcap's
    ///     installation directory to one of the window's system folders. This
    ///     could be \windows or \windows\system32 directory.

	//PSH is an indication by the sender that, if the receiving machine's TCP implementation has not yet provided 
	//the data it's received to the code that's reading the data (program, or library used by a program), it should do so at that point.
	
	public static void main(String[] args){
		String pcapFile = "assignment2.pcap";
		ArrayList<byte[]> packetsFromFile = readPacktsFromFile(pcapFile);
		long[][] table = new long[packetsFromFile.size()][3];// 0:seq 1:ack 2:rwind 
		ArrayList<Integer> theFlowPortNums = new ArrayList<Integer>();
		
		ArrayList<ArrayList<byte[]>> whoa = new ArrayList<ArrayList<byte[]>>(); 
		
		for(int i=0;i<packetsFromFile.size();i++){ //this will go through each packet
						
				int byte34 = packetsFromFile.get(i)[34];//34 and 35 for port numb
				if(byte34<0){byte34+=256;}
				int byte35 = packetsFromFile.get(i)[35];
				if(byte35<0){byte35+=256;}
				
				int oPort = (byte34<<8)+byte35;			
						
				int byte36 = packetsFromFile.get(i)[36];//34 and 35 for port numb
				if(byte36<0){byte36+=256;}
				int byte37 = packetsFromFile.get(i)[37];
				if(byte37<0){byte37+=256;}
				
				int rPort = (byte36<<8)+byte37;
				
			if(packetsFromFile.get(i)[47]==2){  // packet of type SYN is sent, initiating a new TCP flow  1 would be for FIN and 16 for ACK
				
				theFlowPortNums.add(oPort); //this number will match the list of its port
				numFlows++;
				whoa.add(new ArrayList<byte[]>());
				
			}
			for(int j=0;j<theFlowPortNums.size();j++){
				if(theFlowPortNums.get(j) == oPort || theFlowPortNums.get(j) == rPort){
					whoa.get(j).add(packetsFromFile.get(i));
					
				}
			}
			
			//Sequence Number Calculation// bytes 38-41
			long seqNum=0;
			int byte38 = packetsFromFile.get(i)[38];
			if(byte38<0){byte38+=256;}
			seqNum = (long)byte38;
			int byte39 = packetsFromFile.get(i)[39];
			if(byte39<0){byte39+=256;}
			seqNum = (seqNum << 8) + (long)byte39;
			int byte40 = packetsFromFile.get(i)[40];
			if(byte40<0){byte40+=256;}
			seqNum = (seqNum << 8) + (long)byte40;
			int byte41 = packetsFromFile.get(i)[41];
			if(byte41<0){byte41+=256;}
			seqNum = (seqNum << 8) + (long)byte41;
			/*if(i==0){
				BigInteger a = new BigInteger(Integer.toString(byte38));
				a = a.shiftLeft(8).add(new BigInteger(Integer.toString(byte39)));
				a = a.shiftLeft(8).add(new BigInteger(Integer.toString(byte40)));
				a = a.shiftLeft(8).add(new BigInteger(Integer.toString(byte41)));
				
				System.out.println(byte38 + " " + byte39 + " " + byte40 + " " + byte41);
				
				System.out.println(a);
				System.out.println(seqNum);
			}*/ //keeping this just in case numbers get too large to handle with longs
			table[i][0] = seqNum;
			//end Sequence Number Calculation//
			
			
			//Acknowledgement calculation//  bytes 42-45 (tried different technique here as far as bit shifting, works just the same)
			long ackNum = 0;
			int byte42 = packetsFromFile.get(i)[42];
			if(byte42<0){byte42+=256;}
			ackNum+= ((long)(byte42))<<24;
			int byte43 = packetsFromFile.get(i)[43];
			if(byte43<0){byte43+=256;}
			ackNum+= ((long)(byte43))<<16;
			int byte44 = packetsFromFile.get(i)[44];
			if(byte44<0){byte44+=256;}
			ackNum+= ((long)(byte44))<<8;
			int byte45 = packetsFromFile.get(i)[45];
			if(byte45<0){byte45+=256;}
			ackNum+= (long)byte45;
			table[i][1] = ackNum;
			//end Acknowledgement calculation//
			
			//Receiving Window Calculation//
			int byte48 = packetsFromFile.get(i)[48];
			if(byte48<0){ byte48+=256;}
			int byte49 = packetsFromFile.get(i)[49];
			if(byte49<0){ byte49+=256;}
			long rWindow = (byte48 << 8)+ byte49;
			table[i][2] = rWindow;
			//end Receiving Window Calculation//
		}
			
			
			System.out.println(table[0][2]);
			System.out.println(table[67][1]);
			System.out.println(theFlowPortNums.toString()); 
			System.out.println(whoa.get(0).size() + whoa.get(1).size() + whoa.get(2).size());
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
		pcap.close();
		return packets;
	}

	
}