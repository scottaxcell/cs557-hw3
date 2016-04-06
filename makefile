all:
	g++ -std=c++11 fdscan.cxx -o fdscan -lpcap
clean:
	rm -f fdscan
