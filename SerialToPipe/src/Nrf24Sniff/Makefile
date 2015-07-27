# NRF24Sniff -- Makefile
#
# Copyright (c) 2015 by Dietmar Malli <dietmar@malli.co.at>
#
# This file is part of NRF24Sniff.
# 
# NRF24Sniff is free software: you can redistribute 
# it and/or modify it under the terms of the GNU General Public 
# License as published by the Free Software Foundation, either 
# version 3 of the License, or (at your option) any later version.
# 
# NRF24Sniff is distributed in the hope that it will 
# be useful, but WITHOUT ANY WARRANTY; without even the implied warranty 
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with NRF24Sniff.  If not, see <http://www.gnu.org/licenses/>.
#
# @license GPL-3.0+ <http://spdx.org/licenses/GPL-3.0+>

#Precompiler can only compare numbers... WINDOWS=0 LINUX=1
OS = 1

ifeq ($(OS),0)
    OUTPUT = Nrf24Sniff.exe
    SRC = $(wildcard *.cpp)
else
    OUTPUT = Nrf24Sniff
    SRC = $(wildcard *.cpp)
    SRC := $(filter-out XGetopt.cpp,$(SRC))
endif

CC=g++
#CFLAGS:add -m32 to compile for 32bit on 64bit machine...
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