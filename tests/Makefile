CC = g++
CPPFLAGS = -g -DFIPS -std=c++98 -DGTEST_HAS_PTHREAD=0
EXECUTABLE = test.out

LIBCRYPTOSEC = ../libcryptosec.so
LIBS = $(LIBCRYPTOSEC) -lgtest
SRC_DIR = src/unit
SSL_INCLUDES = -I/home/labsec/Desktop/openssl-1.0.2q/include
INCLUDES = -I../include/ -I/usr/include/gtest $(SSL_INCLUDES)

TEST_SRCS += $(wildcard $(SRC_DIR)/*.cpp)
OBJS += $(TEST_SRCS:.cpp=.o)

%.o: %.cpp
	@echo 'Building file: $<'
	$(CC) $(CPPFLAGS) $(INCLUDES) -O0 -Wall -c -o "$@" "$<"
	@echo ' '

all: check-lib $(OBJS)
	$(CC) $(CPPFLAGS) -o $(EXECUTABLE) $(OBJS) $(LIBS)
	@echo 'Build complete!'
	@echo ' '

check-lib:
	@test -s $(LIBCRYPTOSEC) || { echo "You should install libcryptosec first!"; exit 1; }

test: all
	@echo 'Building libcryptosec'
	@echo 'Executing tests...'
	./$(EXECUTABLE)
	@echo 'Done!'

clean:
	rm -rf ./$(SRC_DIR)/*.o $(EXECUTABLE)
