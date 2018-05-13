CC     = gcc
CFLAGS = -Wall -Wextra
OFLAGS = -lssl -lcrypto
OBJ    = certcheck.o
EXE    = certcheck

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ) $(OFLAGS)

clean:
	rm $(OBJ) $(EXE)

scp:
	scp *.c *.pem Makefile ubuntu@115.146.93.189:comp30023/Assignment2
	scp -r sample_certs ubuntu@115.146.93.189:comp30023/Assignment2
