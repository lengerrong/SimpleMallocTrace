all:
	@make clean
	@mkdir out
	g++ -g -o out/smtest smtest.cpp simplemtrace.c -ldl -lpthread

clean:
	@rm out -rf
