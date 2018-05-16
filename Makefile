CC     = gcc
CFLAGS = -Wall -Wextra -lssl -lcrypto
OBJ    = certcheck.o certlist.o filehandle.o verify.o
EXE    = certcheck

$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS)

clean:
	rm $(OBJ) $(EXE)

scp:
	scp *.c *.h*.pem Makefile ubuntu@115.146.93.189:comp30023/Assignment2
	scp -r sample_certs ubuntu@115.146.93.189:comp30023/Assignment2
