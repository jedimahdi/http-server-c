build:
	gcc main.c pm_loop.c pm_reader.c pm_writer.c pm_ringbuf.c utils.c -g -Og -luring -D_GNU_SOURCE -o main
