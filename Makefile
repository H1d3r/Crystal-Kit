all:
	cd udrl && make $@
	cd postex-udrl && make $@

debug:
	cd udrl && make $@
	cd postex-udrl && make $@

clean:
	cd udrl && make $@
	cd postex-udrl && make $@