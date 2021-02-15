LIB=libperftools
default: $(LIB).so

.PHONY: clean

$(LIB).so: $(LIB).cc
	g++ -shared -fPIC -o $@ $<

clean:
	rm -f *.so
