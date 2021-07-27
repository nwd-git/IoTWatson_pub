BIN:=watson
.PHONY: all clean

all: $(BIN)

$(BIN): main.c
	$(CC) -o $@ $^ -luci -lubox -lubus -liotp-as-device

clean:
	rm -f $(BIN)
