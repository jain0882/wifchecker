default:
	gcc -O3 -g -c gmpecc.c -o gmpecc.o
	gcc -O3 -g -c queue.c -o queue.o
	gcc -O3 -g -c threadpool.c -o threadpool.o
	gcc -g -o wif_checker wif_checker.c gmpecc.o queue.o threadpool.o -lgmp -lm -lpthread -lrt -lcrypto
clean:
	rm wif_checker
	rm -r *.o
