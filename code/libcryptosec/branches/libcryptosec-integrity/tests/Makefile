LIBS = -lcryptosec
INCLUDES = -I./$(GTEST_DIR) -I/usr/include/libcryptosec
CC = g++
CPPFLAGS = -DGTEST_HAS_PTHREAD=0
CXXFLAGS = -g
EXECUTABLE = test.out

GTEST_DIR = gtest
SRC_DIR = src

TEST_SRCS += $(wildcard $(SRC_DIR)/*.cpp)
OBJS += $(TEST_SRCS:.cpp=.o)

%.o: %.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) -O0 -Wall -c -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

all:	gtest $(OBJS)
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(LIBS) -o $(EXECUTABLE) $(OBJS) ./$(GTEST_DIR)/gtest-all.o
	@echo 'Build complete!'
	@echo ' '

gtest: ./$(GTEST_DIR)/gtest-all.o

test:
	@echo 'Executing tests...'
	./$(EXECUTABLE)
	@echo 'Done!'

clean:
	rm -rf ./$(SRC_DIR)/*.o $(EXECUTABLE)

veryclean: clean
	rm -rf ./$(GTEST_DIR)/*.o
