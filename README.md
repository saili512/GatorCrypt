# GatorCrypt
A file encryption/decryption/transmission suite akin to scp with HMAC for authentication using gcrypt libraries

The file encryption programs gatorcrypt and gatordec take the following inputs:

gatorcrypt <input file> [-d < IP-addr:port >][-l]

gatordec <filename>  [-d < port >][-l] 
	    

where gatorcrypt takes an input file and transmits it to the IP address/port specified on the command-line (-d option),
or dumps the encrypted contents of the input file to an output file of the same name, but with the added extension '.uf'
e.g., if the input file is hello.txt, the output file will be hello.txt.uf.

The gatordec runs as a network daemon (-d), awaiting incoming network connections on the command-line specified network
port. When a connection comes in, it writes the file data to "filename" and exits. 
gatordec can also be run in local mode (-l) in which it bypasses the network functionality and simply decrypts a file
specified as input. It is assumed that the input file (for decryption) ends ".uf", so the output will be the original 
filename without this additional extension. (This is simply the inverse of gatorcrypt).
