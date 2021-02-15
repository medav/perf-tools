
default: app

.PHONY: clean

app: app.cc
	g++ -pthread -o $@ $< -I../include $(EXTRAFLAGS)

clean:
	rm -f app