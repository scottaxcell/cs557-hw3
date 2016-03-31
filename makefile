all:
	g++ -std=c++11 -Wall fdscan.cxx -o fdscan -lpcap
clean:
	rm -f fdscan
