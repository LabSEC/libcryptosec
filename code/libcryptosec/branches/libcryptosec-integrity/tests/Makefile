LIBS = -lcryptosec
INCLUDES = -I./$(GTEST_DIR) -I/usr/include/libcryptosec
CC = g++
CPPFLAGS = -DGTEST_HAS_PTHREAD=0
CXXFLAGS = -g
EXECUTABLE = test.out

GTEST_DIR = gtest
SRC_DIR = src

TEST_SRCS += \
./$(GTEST_DIR)/gtest-all.cpp \
./$(SRC_DIR)/Main.cpp \
./$(SRC_DIR)/TesteExemplo.cpp \

all: compile test

compile:
	$(CC) $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(LIBS) $(TEST_SRCS) -o $(EXECUTABLE)

test:
	./$(EXECUTABLE)

clean:
	rm $(EXECUTABLE)

#TODO
#CPP_TEST_SRCS += 
#
#TEST_OBJS += $(CPP_TEST_SRCS:.cpp=.o)
#
# Verificar se precisa de DEPS para os testes. Teste é apenas executado, nunca instalado.
#CPP_TEST_DEPS += $(CPP_TEST_SRCS:.cpp=.d)
