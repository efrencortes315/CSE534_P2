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
	static ArrayList<BigInteger> totalBytes = new ArrayList<BigInteger>();
	static ArrayList<Long> beginAcks = new ArrayList<Long>();
	static ArrayList<Long> endAcks = new ArrayList<Long>();
	static ArrayList<ArrayList<Long>> listsOfSentSeqs = new ArrayList<ArrayList<Long>>();
	static ArrayList<Integer> numReTrans = new ArrayList<Integer>();
	static ArrayList<Integer> numPacketsSent = new ArrayList<Integer>();
	static ArrayList<Long> endingTimes = new ArrayList<Long>();
	//  javac -classpath jnetpcap.jar analysis_pcap_tcp.java to compile using the imported library
	
	///     copy the jnetpcap.dll library file, found at root of jnetpcap's
    ///     installation directory to one of the window's system folders. This
    ///     could be \windows or \windows\system32 directory.

	//PSH is an indication by the sender that, if the receiving machine's TCP implementation has not yet provided 
	//the data it's received to the code that's reading the data (program, or library used by a program), it should do so at that point.
	
	public static void main(String[] args){
		String pcapFile = "assignment2.pcap";
		ArrayList<byte[]> packetsFromFile = readPacktsFromFile(pcapFile); // reads packets from file and converts into accessible byte array
		
		ArrayList<Integer> theFlowPortNums = new ArrayList<Integer>(); // finds each outgoing port number, signifying each different flow initiated
		long[][] table = packInfo(theFlowPortNums, packetsFromFile);// 0:seq 1:ack 2:rwind 3:sendPort 4:receivePort
		
		
			
		
		outputPacketInfo(theFlowPortNums,table, 20); //takes all of the information and displays neatly, the first n transactions per flow
			
			
			
			
		
			
		
	}
	
	public static void outputPacketInfo(ArrayList<Integer>theFlowPortNums, long[][]table, int length){
		int i=0;
			int j=0;
		System.out.println("Total of number of flows initiated by the sender is: " + numFlows);
		System.out.println();
		
		for(int q = 0;q<theFlowPortNums.size();q++){
			
			while(i<length){
				
				if(theFlowPortNums.get(q)== table[j][3] || theFlowPortNums.get(q)==table[j][4]){
					//if(initSeq<=0){initSeq=table[j][0];}
					//if(initAck<=0){initAck=table[j][1];}
					String asl="";
					String asb="";
					if(table[j][3]==80){asl = "\t";}
					if(table[j][1]==0){asb = "\t";}
					System.out.println("Seq: " + table[j][0] + "\t\tAck: " + table[j][1] + asb + "\t\tRWind: " + table[j][2] + "\t\tFrom:" + table[j][3] +asl+ "\tTo: " + table[j][4]);
					i++;
				
				}
			j++;
			}
			System.out.println();
			System.out.println("Total outgoing bytes for entire flow: " + totalBytes.get(q).toString());
			System.out.println("Total outgoing packets for entire flow: " + numPacketsSent.get(q).toString());
			System.out.println("Total number of retransmissions for entire flow: " + numReTrans.get(q).toString());
			i=0;
			j=0;
			System.out.println();System.out.println();
			//delete this for loop to restore
		}
	}
	public static long[][] packInfo(ArrayList<Integer>theFlowPortNums, ArrayList<byte[]> packetsFromFile){
		long[][] table = new long[packetsFromFile.size()][5];
		/*boolean start = false;
		boolean end = false;*/
		for(int i=0;i<packetsFromFile.size();i++){ //this will go through each packet
						
				int byte34 = packetsFromFile.get(i)[34];//34 and 35 for port numb
				if(byte34<0){byte34+=256;}
				int byte35 = packetsFromFile.get(i)[35];
				if(byte35<0){byte35+=256;}
				
				int oPort = (byte34<<8)+byte35;			
				table[i][3] = oPort;
				int byte36 = packetsFromFile.get(i)[36];//34 and 35 for port numb
				if(byte36<0){byte36+=256;}
				int byte37 = packetsFromFile.get(i)[37];
				if(byte37<0){byte37+=256;}
				
				int rPort = (byte36<<8)+byte37;
				table[i][4] = rPort;
			if(packetsFromFile.get(i)[47]==2){  // packet of type SYN is sent, initiating a new TCP flow  1 would be for FIN and 16 for ACK
				
				theFlowPortNums.add(oPort); //this number will match the list of its port
				totalBytes.add(new BigInteger("0"));
				//start=true;
				listsOfSentSeqs.add(new ArrayList<Long>());
				numReTrans.add(0);
				numPacketsSent.add(0);
				numFlows++;
				endingTimes.add((long)0);
				
			}
			long timeStamp = 0;
			if(packetsFromFile.get(i)[47]==17){
				
				int byte62 = packetsFromFile.get(i)[62];
				if(byte62<0){byte62+=256;}
				timeStamp = (long)byte62;
				int byte63 = packetsFromFile.get(i)[63];
				if(byte63<0){byte63+=256;}
				timeStamp = (timeStamp<<8) + (long)byte63;
				int byte64 = packetsFromFile.get(i)[64];
				if(byte64<0){byte64+=256;}
				timeStamp = (timeStamp<<8) + (long)byte64;
				int byte65 = packetsFromFile.get(i)[65];
				if(byte65<0){byte65+=256;}
				timeStamp = (timeStamp<<8) + (long)byte65;
				
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
			table[i][2] = rWindow; //apparently, besides in the initial handshake, 
			//end Receiving Window Calculation//
			
			for(int q=0;q<theFlowPortNums.size();q++){
				if(timeStamp!=0 && theFlowPortNums.get(q)==rPort){
					endingTimes.add(timeStamp);
				}
				if(rPort==80 && theFlowPortNums.get(q)==oPort){
					totalBytes.set(q, totalBytes.get(q).add(new BigInteger(Long.toString(packetsFromFile.get(i).length)))); //adds total bytes outgoing
					numPacketsSent.set(q,numPacketsSent.get(q)+1);
					if(listsOfSentSeqs.get(q).contains(seqNum)){
						//System.out.println("Retransmission");
						numReTrans.set(q,numReTrans.get(q)+1);
					}else{
						listsOfSentSeqs.get(q).add(seqNum);//adds the seq to a list, to later check for retransmissions
					}
				}
				
			}
		}
		return table;
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