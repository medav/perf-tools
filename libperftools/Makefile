LIB=libperftools
default: $(LIB).so

.PHONY: clean

$(LIB).so: $(LIB).cc ../include/pin-perf.hh ../include/counter-perf.hh
	g++ -shared -fPIC -o $@ $< -I../include

clean:
	rm -f *.so
