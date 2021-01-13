


app: app.cc
	g++ -o $@ $< -I../include $(EXTRAFLAGS)

.PHONY: pinver

pinver:
	$(MAKE) -C. app EXTRAFLAGS=-DPINTOOL