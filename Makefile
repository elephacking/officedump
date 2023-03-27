# Makefile

# Set the name of the output executable
OUTFILE = officedump.exe

# Set the path to the cross-compiler for Windows
CC = x86_64-w64-mingw32-gcc

# Set the compiler flags
CFLAGS = -Wall -Wextra -Wpedantic -Werror

# Set the linker flags
LDFLAGS =

# List the source files
SRCS = officedump.c

# Define the object files
OBJS = $(SRCS:.c=.o)

all: $(OUTFILE)

$(OUTFILE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(OUTFILE)
