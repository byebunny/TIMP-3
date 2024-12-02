.PHONY: all debug release clean

Compiler = g++
RELEASE_EXEC  = Gron
DEBUG_EXEC    = Grons-dbg 
SOURCES       = test_2.cpp modAlphaCipher.cpp
Libary        = -lUnitTest++
all: debug release

debug: $(DEBUG_EXEC)

$(DEBUG_EXEC): $(SOURCES)
	$(Compiler) $(SOURCES) -o $(DEBUG_EXEC) $(Libary)

release: $(RELEASE_EXEC)

$(RELEASE_EXEC): $(SOURCES)
	$(Compiler)  $(SOURCES) -o $(RELEASE_EXEC) $(Libary)

clean:
	rm -f $(RELEASE_EXEC) $(DEBUG_EXEC)
