LIBS = -lcryptosec
INCLUDES = -I./$(GTEST_DIR) -I/usr/include/libcryptosec
CC = g++
CPPFLAGS = -DGTEST_HAS_PTHREAD=0
CXXFLAGS = -g
EXECUTABLE = test.out

GTEST_DIR = gtest
SRC_DIR = src
LIBCRYPTOSEC = /usr/lib/libcryptosec.so

TEST_SRCS += $(wildcard $(SRC_DIR)/*.cpp)
OBJS += $(TEST_SRCS:.cpp=.o)

%.o: %.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) -O0 -Wall -c -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

all:	check-lib gtest $(OBJS)
	$(CC) $(CPPFLAGS) $(CXXFLAGS) -o $(EXECUTABLE) $(OBJS) ./$(GTEST_DIR)/gtest-all.o $(LIBS)
	@echo 'Build complete!'
	@echo ' '

check-lib:
	@test -s $(LIBCRYPTOSEC) || { echo "You should install libcryptosec first!"; exit 1; }

check-test:
	@test -s $(EXECUTABLE) || { echo "You should compile the tests first!"; exit 1; }
	
gtest: ./$(GTEST_DIR)/gtest-all.o

test:	check-test
	@echo 'Executing tests...'
	./$(EXECUTABLE)
	@echo 'Done!'

clean:
	rm -rf ./$(SRC_DIR)/*.o $(EXECUTABLE)

veryclean: clean
	rm -rf ./$(GTEST_DIR)/*.o
