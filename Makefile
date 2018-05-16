CC     = gcc
CFLAGS = -Wall -Wextra -lssl -lcrypto
OBJ    = certcheck.o certlist.o filehandle.o verify.o
EXE    = certcheck

$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS)

clean:
	rm $(OBJ) $(EXE)

scp:
	scp *.c *.h *.pem *.sh Makefile ubuntu@115.146.93.189:comp30023/Assignment2
	scp -r sample_certs ubuntu@115.146.93.189:comp30023/Assignment2

test:
	chmod +x ./run.sh
	./run.sh

vpn:
	gnome-terminal -- sudo openconnect -u dhaliwala https://remote.unimelb.edu.au/student
