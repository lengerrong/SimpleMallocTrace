all:
	@mkdir out
	g++ -g -o out/smtest smtest.cpp simplemtrace.c -ldl

clean:
	@rm out -rf
