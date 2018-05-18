CC     = gcc
CFLAGS = -Wall -Wextra -lssl -lcrypto
OBJ    = certcheck.o certlist.o filehandle.o verify.o
EXE    = certcheck

$(EXE): $(OBJ)
	$(CC) -o $(EXE) $(OBJ) $(CFLAGS)

clean:
	rm $(OBJ) $(EXE)

run:
	./certcheck ./sample_certs/sample_input.csv
	./testscript.sh
memory:
	valgrind --leak-check=full ./certcheck ./sample_certs/sample_input.csv

copy:
	rsync -ru *.c *.h *.pem *.sh Makefile ubuntu@115.146.93.189:comp30023/Assignment2
	rsync -ru -r sample_certs ubuntu@115.146.93.189:comp30023/Assignment2

test:
	chmod +x ./run.sh
	./run.sh
