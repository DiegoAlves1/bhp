#coding: utf-8
import sys
import socket
import threading

def hexdump(src, length=16):

	result = []
	digits = 4 if isinstance(src, unicode) else 2

	for i in xrange(0, len(src), length):
		s = src[i:i+length]

		hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
		text = b' '.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
		result.append( b"%04X   %-*s  %s" % (i, length*(digits + 1), hexa, text) )
	
	print b'\n'.join(result)

def receive_from(connection):
        
        buffer = ""

	# We set a 2 second time out depending on your 
	# target this may need to be adjusted
	connection.settimeout(2)
	
        try:
                # keep reading into the buffer until there's no more data
		# or we time out
                while True:
                        data = connection.recv(4096)
                        
                        if not data:
                                break
                        
                        buffer += data
                
                
        except:
		pass
        
        return buffer
def request_handler(buffer):
	# faz modificações no pacote

	return buffer

# modofica qualquer resposta destinada ao host local

def response_handler(buffer):
	# faz modificações no pacote

	return buffer



def proxy_handler(client_socket, remote_host, remote_port, receive_first):
        
        # connect to the remote host
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((remote_host,remote_port))

        # receive data from the remote end if necessary
        if receive_first:
                
                remote_buffer = receive_from(remote_socket)
                hexdump(remote_buffer)
		
                # send it to our response handler
		remote_buffer = response_handler(remote_buffer)
                
                # if we have data to send to our local client send it
                if len(remote_buffer):
                        print "[<==] Enviando %d bytes para localhost." % len(remote_buffer)
                        client_socket.send(remote_buffer)
                        
	# now let's loop and reading from local, send to remote, send to local
	# rinse wash repeat
while True:
		
		# read from local host
		local_buffer = receive_from(client_socket)


		if len(local_buffer):	
			
			print "[==>] Recebendo %d bytes from localhost." % len(local_buffer)
			hexdump(local_buffer)
			
			# send it to our request handler
			local_buffer = request_handler(local_buffer)
			
			# send off the data to the remote host
			remote_socket.send(local_buffer)
			print "[==>] Enviar para remoto."
		
		
		# receive back the response
		remote_buffer = receive_from(remote_socket)

		if len(remote_buffer):
			
			print "[<==] Recebendo %d bytes para remoto." % len(remote_buffer)
			hexdump(remote_buffer)
			
			# send to our response handler
			remote_buffer = response_handler(remote_buffer)
		
			# send the response to the local socket
			client_socket.send(remote_buffer)
			
			print "[<==] Enviando para localhost."
		
		# if no more data on either side close the connections
		if not len(local_buffer) or not len(remote_buffer):
			client_socket.close()
			remote_socket.close()
			print "[*] Sem mais arquivos. Fechando conexões."
		
			break
	
def server_loop(local_host,local_port,remote_host,remote_port,receive_first):

	server = socket.socket(socket.AF_INET, socket,SOCK_STREAM)

	try:

		server.bind((local_host,local_port))

	except:
		print "[!!] Falha em escutar no %s:%d" % (local_host,local_port)
		print "[!!] Procure por outras escutas sockets ou corrija as permissões."
		sys.exit(0)

	print "[*] Escutando no %s:%d" % (local_host,local_port)

	server.listen(5)

	while True:
		client_socket, addr = server.accept()

		# exibe informações sobre a conexão local

		print "[==>] Esperando receber conexão do %s:%d" % (addr[0],addr[1])

		# inicia uma thread para conversar com o host remoto
		proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket,remote_host,remote_port,receive_first))

		proxy_thread.start()

def main():


	# sem parsing sofisticado de linha de comando nesse caso

	if len(sys.argv[1:]) != 5:
		print "Usar: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]"
		print "Exemplo: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
		sys.exit(0)


	# define parâmetros para ouvir localmente

	local_host = sys.argv[1]
	local_port = int(sys.argv[4])

	# o código a seguir diz ao nosso proxy para conectar e receber dados
	# antes de enviar ao host remoto
	receive_first = sys.argv[5]

	if "True" in receive_first:
		receive_first = True
	else:
		receive_first = False

	# agora coloca em ação o nosso socket que ficará ouvindo

	server_loop(local_host,local_port,remote_host,remote_port,receive_first)

main()