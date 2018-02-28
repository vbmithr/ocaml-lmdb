all:
	jbuilder build @install @runtest-lmdb

clean:
	rm -rf _build
