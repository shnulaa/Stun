package tk.liuyq.stun;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;


/**
 * Stun Get Nat Type
 * 
 * @author liuyq
 *
 */
public class Stun {
  /* empty body length for request */
  static final int BODY_LENGTH_EMPTY = 0x0000;

  /* attribute length of change request for ip and Port */
  static final int ATTR_LENGTH_CHNANGE_REQUEST = 0x0004;

  /* attribute length of change request for Port */
  static final int ATTR_LENGTH_CHNANGE_PORT_REQUEST = 0x0002;

  /* Attribute type of CHNANGE_REQUEST IP and port */
  static final int CHNANGE_REQUEST_IP_PORT = 0x000006;

  /* Attribute type of CHNANGE_REQUEST port */
  static final int CHNANGE_REQUEST_PORT = 0x000002;

  /* Request of transId */
  static final String TRANID = getTransId();

  /* STUN Message type */
  static final int BINDING_REQUEST = 0x0001; // binding request
  static final int BINDING_RESPONSE = 0x0101; // binding response
  static final int BINDING_ERROR_RESPONSE = 0x0111; // binding error response
  static final int SHARED_SECRET_REQUEST = 0x0002; // shared secret request
  static final int SHARED_SECRET_RESPONSE = 0x0102; // shared secret response
  static final int SHARED_SECRET_ERROR_RESPONSE = 0x0112; // shared secret error response

  /* STUN Attribute type */
  static final int STUN_MAPPED_ADDRESS = 0x0001; // stun_mapped_address
  static final int STUN_RESPONSE_ADDRESS = 0x0002; // stun_response_address
  static final int STUN_CHANGE_REQUEST = 0x0003; // stun_change_request
  static final int STUN_SOURCE_ADDRESS = 0x0004; // stun_source_address
  static final int STUN_CHANGED_ADDRESS = 0x0005; // stun_changed_address
  static final int STUN_USERNAME = 0x0006; // stun_username
  static final int STUN_PASSWORD = 0x0007; // stun_password
  static final int STUN_MESSAGE_INTEGRITY = 0x0008; // stun_message_integrity
  static final int STUN_ERROR_CODE = 0x0009; // stun_error_code
  static final int STUN_UNKNOWN_ATTRIBUTES = 0x000A; // stun_unknown_attributes
  static final int STUN_REFLECTED_FROM = 0x000B; // stun_reflected_from
  static final int STUN_REALM = 0x0014; // stun_realm
  static final int STUN_NONCE = 0x0015; // stun_nonce
  static final int STUN_XOR_MAPPED_ADDRESS = 0x0020; // stun_xor_mapped_address

  /** default socket timeout **/
  static final int SOCKET_TOMEOUT = 5000;

  /**
   * Parse Stun Response Raw
   * 
   * Stun request Header <hr>
   *    0                   1                   2                   3   <br>
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  <br>
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   *   |0 0|     STUN Message Type     |         Message Length        | <br>
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   *   |                         Magic Cookie                          | <br>
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   *   |                                                               | <br>
   *   |                     Transaction ID (96 bits)                  | <br>
   *   |                                                               | <br>
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   * 
   *  Stun Request Body  <hr>
   *    0                   1                   2                   3    <br>
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 <br>
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   *   |         Type                  |            Length             | <br>
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   *   |                         Value (variable)                ....    <br>
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <br>
   * 
   * @param responseRaw Stun response byte array
   * @return
   */
  private Map<String, String> parseResponseRaw(byte[] responseRaw) {
    // Byte array Change to ByteBuffer
    ByteBuffer response = ByteBuffer.wrap(responseRaw);

    // Get stun message type (16 bit, 2 bytes)
    byte[] messageType = new byte[2];
    response.get(messageType, 0, 2);

    // Get message Length (16 bit, 2 bytes)
    byte[] bodyLength = new byte[2];
    response.get(bodyLength, 0, 2);
    int attrBodyLength = (((bodyLength[0] & 0xFF) << 8) | bodyLength[1]);

    // Get the message transId (fix 96 bits 16 byte)
    byte[] transId = new byte[16];
    response.get(transId, 0, 16);

    // get Attribute body (byte.length = length)
    byte[] attrs = new byte[attrBodyLength];
    response.get(attrs, 0, attrBodyLength);

    // Attribute Type
    ByteBuffer byteBufferAttrs = ByteBuffer.wrap(attrs);
    Map<String, String> mapRet = new LinkedHashMap<>();

    // Loop the Attribute Byte buffer until remain size is zero
    while (byteBufferAttrs.remaining() > 0) {

      // get the Sun Attribute type (16 bit, 2 bytes)
      byte[] attrsType = new byte[2];
      byteBufferAttrs.get(attrsType, 0, 2);
      int type = (((attrsType[0] & 0xFF) << 8) | attrsType[1]);
      // System.out.println(type);

      // get the Sun Attribute value Length
      byte[] attrLengthBytes = new byte[2];
      byteBufferAttrs.get(attrLengthBytes, 0, 2);
      int attrLength = (((attrLengthBytes[0] & 0xFF) << 8) | attrLengthBytes[1]);
      // System.out.println(attrLength);

      // get the sun Attribute value
      byte[] attrValueBytes = new byte[attrLength];
      byteBufferAttrs.get(attrValueBytes, 0, attrLength);

      // Parse the value to inetAddress
      ByteBuffer attrValue = ByteBuffer.wrap(attrValueBytes);
      attrValue.getShort(); // fix
      int port = attrValue.getShort(); // Port (16 bit 2 byte)
      int A = (int) (0xFF & attrValue.get()); // (8 bit 1 byte 0~255)
      int B = (int) (0xFF & attrValue.get()); // (8 bit 1 byte 0~255)
      int C = (int) (0xFF & attrValue.get()); // (8 bit 1 byte 0~255)
      int D = (int) (0xFF & attrValue.get()); // (8 bit 1 byte 0~255)

      String ip = String.format("%s.%s.%s.%s", A, B, C, D); // ip address
      // System.out.println(String.format("Type:%s, ip:%s, port:%s", type, ip, port));

      // STUN_MAPPED_ADDRESS -> ExternalIP
      if (type == STUN_MAPPED_ADDRESS) {
        mapRet.put("ExternalIP", ip);
        mapRet.put("ExternalPort", String.valueOf(port));
      } else if (type == STUN_SOURCE_ADDRESS) {
        // STUN_SOURCE_ADDRESS -> SourceIP
        mapRet.put("SourceIP", ip);
        mapRet.put("SourcePort", String.valueOf(port));
      } else if (type == STUN_CHANGED_ADDRESS) {
        // STUN_CHANGED_ADDRESS -> ChangedIP
        mapRet.put("ChangedIP", ip);
        mapRet.put("ChangedPort", String.valueOf(port));
      }
    }
    return mapRet;
  }

  /**
   * getNatType
   * 
   * Create UDP Socket and set socket timeout 
   * 
   * @param sourceIp Local source IP
   * @param sourcePort Local source port
   * @param stunHost  stun server host name
   * @param stunPort  stun server port
   * @return Nat type
   * @throws SocketException
   */
  private String getNatType(String sourceIp, int sourcePort, String stunHost, int stunPort)
      throws SocketException {
    try (DatagramSocket socket = new DatagramSocket(sourcePort);) {
      socket.setSoTimeout(SOCKET_TOMEOUT);
      return getNatType(socket, sourceIp, sourcePort, stunHost, stunPort);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * getNatType
   * 
   * include [OpenInternet] [SymmetricUDPFirewall] 
   * [FullCone] [ChangedAddressError] [RestrictNAT] 
   * [RestrictPortNAT] [SymmetricNAT]
   * 
   * @param socket
   * @param sourceIp
   * @param sourcePort
   * @param stunHost
   * @param stunPort
   * @throws IOException
   */
  private String getNatType(DatagramSocket socket, String sourceIp, int sourcePort, String stunHost,
      int stunPort) throws IOException {
    Map<String, String> map = new LinkedHashMap<>();
    if (stunHost != null && !stunHost.isEmpty()) {
      System.out.println(String.format(
          "request to stun server:%s, port:%s, sourceIp:%s, sourcePort:%s, sendDate:%s", stunHost,
          stunPort, sourceIp, sourcePort, "nothing"));
      map = stunRequest(socket, stunHost, stunPort, sourceIp, sourcePort, new byte[] {});
    }

    String exIP = map.get("ExternalIP");
    String exPort = map.get("ExternalPort");
    String changedIP = map.get("ChangedIP");
    String changedPort = map.get("ChangedPort");
    if (sourceIp.equals(exIP)) {
      System.out.println(String.format(
          "(Change host and port)request to stun server:%s, port:%s,"
              + " sourceIp:%s, sourcePort:%s, sendDate:%s due to sourceIp equal exIP,",
          stunHost, stunPort, sourceIp, sourcePort, "nothing"));

      map = stunRequest(socket, stunHost, stunPort, sourceIp, sourcePort,
          constructAttrChangeRequest());
      if (map.size() > 0) {
        return "OpenInternet";
      } else {
        return "SymmetricUDPFirewall";
      }
    } else {
      System.out.println(String.format(
          "(Change port)request to stun server:%s, port:%s,"
              + " sourceIp:%s, sourcePort:%s, sendDate:%s due to sourceIp not equal exIP,",
          stunHost, stunPort, sourceIp, sourcePort, "nothing"));
      map = stunRequest(socket, stunHost, stunPort, sourceIp, sourcePort,
          constructAttrChangeRequest());
      if (map.size() > 0) {
        return "FullCone";
      }

      System.out.println("request to changedIP and changedPort, begin Change Request Test.");
      map = stunRequest(socket, changedIP, Integer.valueOf(changedPort), sourceIp, sourcePort,
          new byte[] {});
      if (map.size() == 0) {
        return "ChangedAddressError";
      }

      // if exIP == ret['ExternalIP'] and exPort == ret['ExternalPort']:
      if (exIP.equals(map.get("ExternalIP")) && exPort.equals(map.get("ExternalPort"))) {
        map = stunRequest(socket, stunHost, stunPort, sourceIp, sourcePort,
            constructAttrChangePortRequest());
        if (map.size() > 0) {
          return "RestrictNAT";
        } else {
          return "RestrictPortNAT";
        }
      } else {
        return "SymmetricNAT";
      }
    }
    // return null;
  }



  /**
   * stunTest
   * 
   * @param socket
   * @param host
   * @param port
   * @param sourceIp
   * @param sourcePort
   * @throws IOException
   */
  private Map<String, String> stunRequest(DatagramSocket socket, String host, int port,
      String sourceIp, int sourcePort, byte[] sendData) throws IOException {
    Map<String, String> map = new LinkedHashMap<>();
    try {
      byte[] raw = constructRequest(sendData);
      // System.out.println(Arrays.toString(raw));
      InetAddress addr = InetAddress.getByName(host);
      DatagramPacket sendPacket = new DatagramPacket(raw, raw.length, addr, port);
      socket.send(sendPacket);
      socket.setReuseAddress(true);

      byte __recv[] = new byte[1024];
      Arrays.fill(__recv, (byte) 0);
      DatagramPacket receivePacket = new DatagramPacket(__recv, 1024);
      socket.receive(receivePacket);
      byte[] responseRaw = receivePacket.getData();
      // System.out.println(Arrays.toString(responseRaw));
      map = parseResponseRaw(responseRaw);
      for (Entry<String, String> e : map.entrySet()) {
        System.out.println(e.getKey() + ":" + e.getValue());
      }
    } catch (Exception e) {
      // e.printStackTrace();
    }

    return map;
  }

  /**
   * get transId
   * 
   * @return
   */
  private static String getTransId() {
    return UUID.randomUUID().toString().replaceAll("-", "").substring(0, 12);
  }


  /**
   * constructRequest
   * 
   * @return
   * @throws UnsupportedEncodingException
   */
  private byte[] constructRequest(byte[] sendData) throws UnsupportedEncodingException {
    ByteBuffer body = ByteBuffer.allocate(20 + sendData.length);

    ByteBuffer header = ByteBuffer.allocate(20);
    header.put((byte) (BINDING_REQUEST >> 8));
    header.put((byte) BINDING_REQUEST);

    if (sendData != null && sendData.length > 0) {
      header.put((byte) (sendData.length >> 8));
      header.put((byte) sendData.length);
    } else {
      header.put((byte) (BODY_LENGTH_EMPTY >> 8));
      header.put((byte) BODY_LENGTH_EMPTY);
    }
    header.put(TRANID.getBytes("UTF-8"));
    byte[] headerBytes = header.array();
    body.put(headerBytes);
    if (sendData != null && sendData.length > 0) {
      body.put(sendData);
    }
    return body.array();
  }

  /**
   * construct attribute Change ip and Port Request
   * 
   * @return
   */
  private byte[] constructAttrChangeRequest() {
    ByteBuffer attrByteBuffer = ByteBuffer.allocate(2 + 2 + 4);
    // attribute type
    attrByteBuffer.put((byte) (STUN_CHANGE_REQUEST >> 8));
    attrByteBuffer.put((byte) (STUN_CHANGE_REQUEST));

    // attribute Length
    attrByteBuffer.put((byte) (ATTR_LENGTH_CHNANGE_REQUEST >> 8));
    attrByteBuffer.put((byte) (ATTR_LENGTH_CHNANGE_REQUEST));

    // attribute value
    attrByteBuffer.put((byte) (CHNANGE_REQUEST_IP_PORT >> 24));
    attrByteBuffer.put((byte) (CHNANGE_REQUEST_IP_PORT >> 16));
    attrByteBuffer.put((byte) (CHNANGE_REQUEST_IP_PORT >> 8));
    attrByteBuffer.put((byte) (CHNANGE_REQUEST_IP_PORT));

    return attrByteBuffer.array();
  }

  /**
   * construct attribute Change Port Request
   * 
   * @return
   */
  private byte[] constructAttrChangePortRequest() {
    ByteBuffer attrByteBuffer = ByteBuffer.allocate(2 + 2 + 4);
    // attribute type
    attrByteBuffer.put((byte) (STUN_CHANGE_REQUEST >> 8));
    attrByteBuffer.put((byte) (STUN_CHANGE_REQUEST));

    // attribute Length
    attrByteBuffer.put((byte) (ATTR_LENGTH_CHNANGE_PORT_REQUEST >> 8));
    attrByteBuffer.put((byte) (ATTR_LENGTH_CHNANGE_PORT_REQUEST));

    // attribute value
    attrByteBuffer.put((byte) (CHNANGE_REQUEST_PORT >> 24));
    attrByteBuffer.put((byte) (CHNANGE_REQUEST_PORT >> 16));
    attrByteBuffer.put((byte) (CHNANGE_REQUEST_PORT >> 8));
    attrByteBuffer.put((byte) (CHNANGE_REQUEST_PORT));
    return attrByteBuffer.array();
  }

  /**
   * print byte to bit
   * 
   * @param b1
   */
  public static void print(byte b1) {
    String s1 = String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
    System.out.println(s1); // 10000001
  }

  /**
   * entry for test
   * @param args
   * @throws SocketException
   */
  public static void main(String[] args) throws SocketException {
    int localPort = 25452;
    if (args.length == 1) {
      localPort = Integer.valueOf(args[0]);
    }
    System.out.println(String.format("localPort:%s", localPort));
    Stun stun = new Stun();
    System.out.println(stun.getNatType("127.0.0.1", localPort, "stun.ekiga.net", 3478));
  }
}
