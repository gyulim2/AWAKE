# C 감시기와 GUI 빌드:  make            → build/awake_monitor, build/awake_gui
#                        make monitor    → GTK 없이 감시기만
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -std=c11
BUILD   := build

all: monitor gui

monitor: $(BUILD)/awake_monitor
gui: $(BUILD)/awake_gui

$(BUILD)/awake_monitor: src/monitor/awake_monitor.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/awake_gui: src/gui/awake_gui.c | $(BUILD)
	$(CC) $(CFLAGS) $$(pkg-config --cflags gtk+-3.0) -o $@ $< $$(pkg-config --libs gtk+-3.0)

$(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)

.PHONY: all monitor gui clean
