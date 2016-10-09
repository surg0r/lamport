__author__ = 'pete'


import pickle #python object serialization of keypair structures for the wallet saving/retrieval
import os
import sys
import json
import merkle
from twisted.internet.protocol import ServerFactory, Protocol
from twisted.internet import reactor



cmd_list = ['balance', 'address', 'wallet', 'send', 'getnewaddress', 'quit', 'exit', 'help', 'savenewaddress', 'listaddresses']

def parse(data):
		return data.replace('\r\n','')

def log(string_data):
    with open("./log/log.txt", "a") as myfile:
        myfile.write(string_data)
    return


def f_read_wallet():

	if os.path.isfile('./wallet.dat') is False:
		print 'Creating new wallet file'
		with open("./wallet.dat", "a") as myfile:				#add in a new call to create random_otsmss
        		pickle.dump(merkle.random_wmss(4), myfile)
        		#myfile.write('')
	

	try:
			with open('./wallet.dat', 'r') as myfile:
				return pickle.load(myfile)
	except:
			print 'IO error'
			return False
	


def f_append_wallet(data):

		data2 = f_read_wallet()
		if data is not False:
			data2 = data2+data
			print 'Appending wallet file'
			with open("./wallet.dat", "w+") as myfile:				#overwrites wallet..
        			pickle.dump(data2, myfile)
		return


			


def inspect_wallet():
	data = f_read_wallet()
	if data is not False:

			num_sigs = []
			num_types = []
			public_keys = []
			for x in range(len(data)): 
				num_sigs.append(0)
				num_types.append(0)
			num_keys = 0
			rootpub = data[0].merkle_root
			public_keys.append(''.join(data[0].merkle_root))
			for keypair in data:
				
				if ''.join(keypair.merkle_root) not in public_keys:
					public_keys.append(''.join(keypair.merkle_root))
					num_keys +=1
					rootpub = keypair.merkle_root 

				if keypair.merkle_root == rootpub:
		
					num_sigs[num_keys] +=1
					num_types[num_keys] = keypair.type

	return public_keys, num_sigs, num_types


class WalletProtocol(Protocol):

	def __init__(self):		#way of passing data back to parent factory - use self.factory.whatever
		pass
		

	def parse_cmd(self, data):

		if data in cmd_list:
			pass
			#self.transport.write('Command: '+data+'\r\n')

			if data == 'getnewaddress':
				new = merkle.random_wmss(4)
				self.transport.write('Keypair type: '+''.join(new[0].type+'\r\n'))
				self.transport.write('Signatures possible with address: '+str(len(new))+'\r\n')
				self.transport.write('Public key: '+''.join(new[0].merkle_root)+'\r\n')
				self.transport.write("type 'savenewaddress' to append to wallet file"+'\r\n')
				self.factory.newaddress = new

			if data == 'savenewaddress':
				if not self.factory.newaddress:
					print 'no new addresses, yet'
					self.transport.write("No new addresses created, yet. Try 'getnewaddress'"+'\r\n')
					return
				f_append_wallet(self.factory.newaddress)
				print 'writing wallet'

			elif data == 'help':
				self.transport.write('QRL ledger help: try quit, balance, wallet, send or getnewaddress'+'\r\n')

			elif data == 'quit' or data == 'exit':
				self.transport.loseConnection()

			elif data == 'listaddresses':
					public_keys, num_sigs, num_types = inspect_wallet()
					
					for x in range(len(public_keys)):
						self.transport.write(str(x+1)+', '+public_keys[x]+'\r\n')

			elif data == 'wallet':
					public_keys, num_sigs, num_types = inspect_wallet()
					
					self.transport.write('Wallet contents:'+'\r\n')
					
					for x in range(len(public_keys)):
						self.transport.write('Wallet keys: type '+num_types[x]+', signatures possible: '+str(num_sigs[x])+'\r\n')
						self.transport.write('Address: '+public_keys[x]+'\r\n')
		else:
			return False

		return True


	def dataReceived(self, data):
		sys.stdout.write('.')
		sys.stdout.flush()
		self.factory.recn += 1
		if self.parse_cmd(parse(data)) == False:
			self.transport.write("Command not recognised. Use 'help' for details"+'\r\n')
	
		

	def connectionMade(self):
		self.transport.write(self.factory.stuff)
		self.factory.connections += 1
		if self.factory.connections > 1:
			print 'only one local connection allowed'
			self.transport.write('only one local connection allowed, sorry')
			self.transport.loseConnection()
		else:
			print '** new local connection', str(self.factory.connections)

	def connectionLost(self, reason):
		print 'lost connection'
		self.factory.connections -= 1

class p2pProtocol(Protocol):

	def __init__(self):		#way of passing data back to parent factory - use self.factory.whatever
		pass

	def parse_cmd(self, data):

		if data in cmd_list:
			pass
			self.transport.write('Command: '+data+'\r\n')

			if data == 'getnewaddress':
				new = merkle.random_wmss(4)
				self.transport.write('Keypair type: '+''.join(new[0].type+'\r\n'))
				self.transport.write('Signatures possible with address: '+str(len(new))+'\r\n')
				self.transport.write('Public key: '+''.join(new[0].merkle_root)+'\r\n')


			elif data == 'help':
				self.transport.write('QRL ledger help: try balance, address, wallet, send or getnewaddress')

			elif data == 'quit' or data == 'exit':
				self.transport.loseConnection()
		else:
			return False

		return True


	def dataReceived(self, data):
		sys.stdout.write('.')
		sys.stdout.flush()
		self.factory.recn += 1
		if self.parse_cmd(parse(data)) == False:
			self.transport.write('Command not recognised. Use help for details'+'\r\n')
	
		

	def connectionMade(self):
		self.transport.write(self.factory.stuff)
		self.factory.connections += 1
		print '** new p2p connection', str(self.factory.connections)

	def connectionLost(self, reason):
		print 'lost connection'
		self.factory.connections -= 1

	
class p2pFactory(ServerFactory):

	protocol = p2pProtocol

	def __init__(self, stuff):
		self.stuff = stuff
		self.recn = 0
		self.connections = 0

class WalletFactory(ServerFactory):

	protocol = WalletProtocol

	def __init__(self, stuff):
		self.newaddress = 0
		self.stuff = stuff
		self.recn = 0
		self.maxconnections = 1
		self.connections = 0


stuff = 'QRL node connection established.'+'\r\n'
port = reactor.listenTCP(2000, WalletFactory(stuff), interface='127.0.0.1')
port2 = reactor.listenTCP(9000, p2pFactory(stuff))

print port.getHost()
print port2.getHost()
print 'QRL blockchain ledger v 0.00'

reactor.run()
