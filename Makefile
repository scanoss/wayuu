CC=gcc
# Enable all compiler warnings. 
CCFLAGS=-g -Wall
# Linker flags
LDFLAGS=-lpthread -lssl -lm -lcrypto -lcurl -I.
# Valgrind flags
VGFLAGS ?= \
	--quiet --leak-check=full --show-leak-kinds=all \
	--track-origins=yes --error-exitcode=1 --keep-debuginfo=yes 

SOURCES=$(wildcard *.c)
# TESTABLE_SOURCES are $SOURCES without main.c
TESTABLE_SOURCES=$(filter-out main.c, $(SOURCES))
TEST_SOURCES=$(wildcard test/*.c) $(wildcard test/**/*.c)
OBJ_TEST=$(patsubst %.c,%.o,$(TEST_SOURCES))
OBJECTS=$(SOURCES:.c=.o)
TESTABLE_OBJECTS=$(filter-out main.o,$(SOURCES:.c=.o))
WAYUU_HEADERS=$(wildcard *.h)
TARGET=wayuu

slib: CCFLAGS:=$(CCFLAGS) -fpic

all: clean $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -g -o $@ $^ $(LDFLAGS)
	rm -f *.o **/*.o 

lib: $(TESTABLE_OBJECTS)
	rm -f libwayuu.a
	$(CC) $(CCFLAGS) -o $@ -c $<
	ar -cvq libwayuu.a *.o
	
slib: $(TESTABLE_OBJECTS)
	$(CC) -g -o libwayuu.so $^ $(LDFLAGS) -shared -fpic
		

%.o: %.c
	$(CC) $(CCFLAGS) -DWAYUU_DIST -o $@ -c $<

test/%.o: test/%.c 
	@mkdir -p $(dir $@)
	$(CC) -DSNOW_ENABLED -I. -Itest/. $(CCFLAGS) -c -o $@ $<

test-$(TARGET): $(OBJ_TEST) $(TESTABLE_OBJECTS)
	$(CC) -g -o $@ $(OBJ_TEST) $(TESTABLE_OBJECTS) $(LDFLAGS)
	
.PHONY: test
test: clean test-$(TARGET)
	valgrind $(VGFLAGS) ./test-$(TARGET) $(ARGS)

run-valgrind: $(TARGET)
	valgrind $(VGFLAGS) ./$(TARGET) -d $(ARGS)

.PHONY: clean
clean:
	rm -f *.o **/*.o test/*.o test/**/*.o $(TARGET) test-$(TARGET)
	
.PHONY: print_src
print_src:
	$(info $$SOURCES is [${SOURCES}])
	$(info $$TESTABLE_SOURCES is [${TESTABLE_SOURCES}])
	$(info $$TESTABLE_OBJECTS is [${TESTABLE_OBJECTS}])
	$(info $$TEST_SOURCES is [${TEST_SOURCES}])
	$(info $$OBJ_TEST is [${OBJ_TEST}])

	
install:
	@cp libwayuu.so /usr/lib
	
	@mkdir -p /usr/include/wayuu

	@cp $(WAYUU_HEADERS) /usr/include/wayuu
