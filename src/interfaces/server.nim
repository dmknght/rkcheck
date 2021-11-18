import net
import os

const
  sockPath* = "/tmp/rkcheck-sock:0"
var
  sockServer* = newSocket(AF_UNIX, SOCK_STREAM, IPPROTO_IP)

type
  DaemonErr* = enum
    SUCCESS, IN_USED


# proc handleRequests*(req: string) =
#   echo "Client requested ", req


proc createServer*(): DaemonErr =
  if fileExists(sockPath):
    return IN_USED
  sockServer.bindUnix(sockPath)
  sockServer.listen()
  return SUCCESS
  # var
  #   client: Socket
  #   address: string
  # while true:
  #   sockServer.acceptAddr(client, address)
  #   let client_request = client.recv(1024, -1)
  #   handleRequests(client_request)


proc closeServer*() =
  sockServer.close()
  if not tryRemoveFile(sockPath):
    echo "Cant remove socket domain path"

proc interruptServer*() {.noconv.} =
  closeServer()

# try:
#   setControlCHook(interruptServer)
#   createServer()
# except Exception:
#   discard
# finally:
#   closeServer()
