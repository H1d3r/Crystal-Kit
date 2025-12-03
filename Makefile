all:
	cd loader && make $@
	cd local-loader && make $@
	cd postex-loader && make $@

clean:
	cd loader && make $@
	cd local-loader && make $@
	cd postex-loader && make $@
