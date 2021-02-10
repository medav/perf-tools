
default: app

.PHONY: clean

app: app.cc ../include/pin-perf.hh
	g++ -o $@ $< -I../include $(EXTRAFLAGS)

clean:
	rm -f app