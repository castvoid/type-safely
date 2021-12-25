from messages_pb2 import MessageWrapper
import binascii

while True:
	str_hex = input("Enter message: ")
	str_raw = binascii.unhexlify(str_hex)

	mw = MessageWrapper()
	mw.ParseFromString(str_raw)
	print()
	print(mw)
	print()
	print()