LIBS = -lcryptosec -lssl -lcrypto
INCLUDES = -I/home/labsec/Desktop/openssl-1.0.2q/include -I./$(GTEST_DIR) -I../include/libcryptosec
CC = g++
CPPFLAGS = -g -DFIPS
EXECUTABLE = test.out


TEST_SRCS += $(wildcard $(SRC_DIR)/*.cpp)
OBJS += $(TEST_SRCS:.cpp=.o)

%.o: %.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) -fPIC $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) -O0 -Wall -c -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

all: check-lib $(OBJS)
	$(CC) -fPIC $(CPPFLAGS) -o $(EXECUTABLE) $(OBJS) $(LIBS)
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
