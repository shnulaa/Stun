package tk.liuyq.stun;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class Server {

  static final int port = 12345;


  public static void main(String[] args) {

    try (DatagramSocket socket = new DatagramSocket(port);) {
      socket.setSoTimeout(10000);
      System.out.println(String.format("listening on port:%s  (udp)", port));

      while (Thread.currentThread().isInterrupted()) {

        byte __recv[] = new byte[1024];
        Arrays.fill(__recv, (byte) 0);
        DatagramPacket receivePacket = new DatagramPacket(__recv, 1024);
        socket.receive(receivePacket);

        byte[] responseRaw = receivePacket.getData();
        String body = new String(responseRaw);

        if (body != null && body.startsWith("msg:")) {

        } else {
          String clientHost = receivePacket.getAddress().getHostAddress();
          int port = receivePacket.getPort();

          System.out.println(String.format("Connection from %s:%s.",
              receivePacket.getAddress().getHostAddress(), receivePacket.getPort()));
          List<String> bodyList = Arrays.asList(body.split(" "));

          Iterator<String> iterator = bodyList.iterator();
          String pool = iterator.next();
          String natTypeId = iterator.next();

          String sendBody = "ok";
          // DatagramPacket sendPacket = new DatagramPacket(sendBody, );
          // socket.send(p);



        }



      }



    } catch (Exception e) {
      throw new RuntimeException(e);
    }


  }


}
