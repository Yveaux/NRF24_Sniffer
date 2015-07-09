OS = WINDOWS

ifeq ($(OS),WINDOWS)
    OUTPUT = Nrf24Sniff.exe
    SRC = $(wildcard *.cpp)
else
    OUTPUT = Nrf24Sniff
    SRC = $(wildcard *.cpp)
    SRC := $(filter-out XGetopt.cpp,$(SRC))
endif

CC=g++
#CFLAGS=inclHeaderDir=./ convertWarn2err linkStatically debugSymbols
CFLAGS=-I. -Wall -DOS=$(OS) -static -g
LDFLAGS=

HEADERS = $(wildcard *.h)
OBJ = $(patsubst %.cpp, %.o, $(SRC))

#First target without . is default target..
all: $(OUTPUT)

#pull in dependency info for *existing* .o files
DEPEND = $(OBJ:.o=.d)
-include $(DEPEND)

#All other recipies
$(OUTPUT): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o $(OUTPUT)

%.o: %.cpp $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)
	gcc -MM $(CFLAGS) $< > $*.d

clean:
	rm -f $(OBJ) $(OUTPUT) $(DEPEND)
	
.PHONY: clean