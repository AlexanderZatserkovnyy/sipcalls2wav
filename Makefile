CC=g++
CXXFLAGS += -g -Wall -O3 --std=c++11
LDLIBS= -lbcg729 -lpq
LDLIBS3 = -lpq
TARGET1_SOURCES = payload2wav.cpp codecParameters.h typedef.h
TARGET2_SOURCES = inotify-payload2wav.cpp codecParameters.h typedef.h
TARGET3_SOURCES = mixwavs.cpp
TARGET4_SOURCES = inotify-mixwavs.cpp

TARGET1 = payload2wav
TARGET2 = inotify-payload2wav
TARGET3 = mixwavs
TARGET4 = inotify-mixwavs

.PHONY: all 1 2 3 4

all: 1 2 3 4
1: $(TARGET1)
2: $(TARGET2)
3: $(TARGET3)
4: $(TARGET4)

$(TARGET1): $(TARGET1_SOURCES) 
	$(CC) $(CXXFLAGS) $^ $(LDLIBS) -o $@

$(TARGET2): $(TARGET2_SOURCES)
	$(CC) $(CXXFLAGS) $^ $(LDLIBS) -o $@

$(TARGET3): $(TARGET3_SOURCES) 
	$(CC) $(CXXFLAGS) $^ $(LDLIBS3) -o $@

$(TARGET4): $(TARGET4_SOURCES)
	$(CC) $(CXXFLAGS) $^ $(LDLIBS3) -o $@

