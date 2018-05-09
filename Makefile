CC     = gcc
CFLAGS = -Wall -Wextra
OBJ    = certcheck.o
EXE    = certcheck

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(OBJ)

clean:
	rm $(OBJ) $(EXE)

scp:
	scp *.c *.h Makefile ubuntu@115.146.93.189:comp30023/Assignment2
