# Makefile for PIN Detection Suite

.PHONY: all run clean help

all:
	./compile_all.sh

run:
	./run_all_evasions.sh

clean:
	rm -f cmodules/bin/*

help:
	@echo "Targets:"
	@echo "  all   - Build all binaries (./compile_all.sh)"
	@echo "  run   - Run all checks (./run_all_evasions.sh)"
	@echo "  clean - Remove all binaries from cmodules/bin/"
	@echo "  help  - Show this help message"
