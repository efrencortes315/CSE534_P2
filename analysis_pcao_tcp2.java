import org.jnetpcap.*;
import java.nio.*;
import java.util.ArrayList; 
import java.util.Arrays;
import java.io.*;
import org.jnetpcap.protocol.tcpip.Tcp;
import java.math.BigInteger;
class analysis_pcap_tcp2{
	static int initCount = 0;
	static int numFlows = 0;
	
	
	public static void main(String[] args){
		String pcapFile = "assignment2.pcap";
		ArrayList<byte[]> packetsFromFile = readPacktsFromFile(pcapFile);
		
		ArrayList<Integer> theFlowPortNums = new ArrayList<Integer>();
		
		ArrayList<ArrayList<byte[]>> whoa = new ArrayList<ArrayList<byte[]>>(); 
		seperateFlows(packetsFromFile, whoa, theFlowPortNums); // we seperate each flow into its own list because we analyze each flow seperately according to the HW
		
		ArrayList<long[][]> tcpFacts = new ArrayList<long[][]>();// 0:seq 1:ack 2:rwind 
		getTcpFacts(tcpFacts, whoa); //here we gather the seq, ack, and rwind and create a new 2d array with this info, for each flow
		
		System.out.println(tcpFacts.get(0)[1][0]); // tcpFacts.get(0) for first flow ... tcpFacts.get(n) for n'th flow, corresponding with 0-n on theFlowPortNums
		
		
	}
	public static void getTcpFacts(ArrayList<long[][]> tcpFacts, ArrayList<ArrayList<byte[]>> whoa){
		for(int i=0;i<numFlows;i++){
			
			tcpFacts.add(new long[whoa.get(i).size()][3]);
			for(int j=0;j<tcpFacts.get(i).length;j++){
				//Sequence Number Calculation// bytes 38-41
				long seqNum = 0;
				int byte38 = whoa.get(i).get(j)[38];
				if(byte38<0){byte38+=256;}
				seqNum = (long)byte38;
				int byte39 = whoa.get(i).get(j)[39];
				if(byte39<0){byte39+=256;}
				seqNum = (seqNum << 8) + (long)byte39;
				int byte40 = whoa.get(i).get(j)[40];
				if(byte40<0){byte40+=256;}
				seqNum = (seqNum << 8) + (long)byte40;
				int byte41 = whoa.get(i).get(j)[41];
				if(byte41<0){byte41+=256;}
				seqNum = (seqNum << 8) + (long)byte41;
				tcpFacts.get(i)[j][0] = seqNum;
				//end Sequence Number Calculation//*/
				
				//Acknowledgement calculation//  bytes 42-45 (tried different technique here as far as bit shifting, works just the same)
				long ackNum = 0;
				int byte42 = whoa.get(i).get(j)[42];
				if(byte42<0){byte42+=256;}
				ackNum+= ((long)(byte42))<<24;
				int byte43 = whoa.get(i).get(j)[43];
				if(byte43<0){byte43+=256;}
				ackNum+= ((long)(byte43))<<16;
				int byte44 = whoa.get(i).get(j)[44];
				if(byte44<0){byte44+=256;}
				ackNum+= ((long)(byte44))<<8;
				int byte45 = whoa.get(i).get(j)[45];
				if(byte45<0){byte45+=256;}
				ackNum+= (long)byte45;
				tcpFacts.get(i)[j][1] = ackNum;
				//end Acknowledgement calculation//
				
				//Receiving Window Calculation//
				int byte48 = whoa.get(i).get(j)[48];
				if(byte48<0){ byte48+=256;}
				int byte49 = whoa.get(i).get(j)[49];
				if(byte49<0){ byte49+=256;}
				long rWindow = (byte48 << 8)+ byte49;
				tcpFacts.get(i)[j][2] = rWindow;
				//end Receiving Window Calculation//
			}
		}
		
	}
	public static void seperateFlows(ArrayList<byte[]> packetsFromFile, ArrayList<ArrayList<byte[]>> whoa, ArrayList<Integer> theFlowPortNums){
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
			int curPos = 0;
			for(int j=0;j<theFlowPortNums.size();j++){
				if(theFlowPortNums.get(j) == oPort || theFlowPortNums.get(j) == rPort){
					whoa.get(j).add(packetsFromFile.get(i));
					curPos = j;
				}
			}
		}
		
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