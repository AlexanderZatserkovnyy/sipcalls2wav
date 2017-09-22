CC=g++
CXXFLAGS += -g -Wall -O3 --std=c++11
LDLIBS= -lbcg729 -lpq 
TARGET1_SOURCES = payload2wav.cpp codecParameters.h typedef.h
TARGET2_SOURCES = inotify-payload2wav.cpp codecParameters.h typedef.h
TARGET1 = payload2wav
TARGET2 = inotify-payload2wav

.PHONY: all 1 2

all: 1 2
1: $(TARGET1)
2: $(TARGET2)

$(TARGET1): $(TARGET1_SOURCES) 
	$(CC) $(CXXFLAGS) $^ $(LDLIBS) -o $@

$(TARGET2): $(TARGET2_SOURCES)
	$(CC) $(CXXFLAGS) $^ $(LDLIBS) -o $@

