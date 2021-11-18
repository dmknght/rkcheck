import net
import interfaces / server


proc createServer() =
  var
    client = newSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP)
  client.connectUnix(sockPath)
  client.send("/home/dmknght/Desktop/MalwareLab/Linux-Malware-Samples/")


createServer()
