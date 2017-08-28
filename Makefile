CC=g++
CXXFLAGS += -g -Wall -O3 --std=c++11
LDLIBS= -lbcg729  
TARGET_SOURCES = G711orG729-2wav.cpp codecParameters.h typedef.h
TARGET = G711orG729-2wav

.PHONY: all 2wav

all: 2wav

2wav: $(TARGET)

$(TARGET): $(TARGET_SOURCES) 
	$(CC) $(CXXFLAGS) G711orG729-2wav.cpp $(LDLIBS) -o $@

