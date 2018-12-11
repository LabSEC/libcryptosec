############# CC FLAGS ###############################
NAME = test.out
CC = g++
CPPFLAGS = -g -std=c++98 -DGTEST_HAS_PTHREAD=0
DEFS = -DFIPS

############# COMP ENVIRONMENT VARIABLES #############
ifndef LIBCRYPTOSEC
LIBCRYPTOSEC = ../libcryptosec.so
endif

ifndef SSL_DIR
SSL_DIR=/usr/local/ssl/include/
endif

ifndef GTEST_INCLUDE
GTEST_DIR=/usr/include/gtest
endif

ifndef SRC_DIR
SRC_DIR = src/unit
endif

ARQ= $(shell uname -m)
LIBDIR = /usr/lib
ifeq ($(ARQ), x86_64)
LIBDIR=/usr/lib64
endif

############ DEPENDENCIES ############################
LIBS = $(LIBCRYPTOSEC) -lgtest -lcrypto -lssl
INCLUDES = -I../include -I$(GTEST_DIR) -I$(SSL_DIR)

########### OBJECTS ##################################
TEST_SRCS += $(wildcard $(SRC_DIR)/*.cpp)
OBJS += $(TEST_SRCS:.cpp=.o)

########### AUX TARGETS ##############################
.set_static:
	$(eval LIBS= $(LIBCRYPTOSEC) -lgtest)

.set_installed:
	$(eval INCLUDES=-I/usr/libcryptosec/include -I$(GTEST_DIR) -I$(SSL_DIR))

.set_engine:
	$(eval DEFS+= -DENGINE_COMP)

.check_compiled:
	@test -s $(LIBCRYPTOSEC) || { echo "You should COMPILE libcryptosec first!"; exit 1; }

.check_installed:
	@test -s $(LIBDIR)/libcryptosec.so || { echo "You should INSTALL libcryptosec first!"; exit 1; }

%.o: %.cpp
	$(CC) $(CPPFLAGS) $(DEFS) $(INCLUDES) -O0 -Wall -c -o "$@" "$<"

.comp: $(OBJS)
	$(CC) $(CPPFLAGS) $(DEFS) -o $(NAME) $(OBJS) $(LIBS)
	@echo 'Build complete!'

.run:
	./$(NAME)
	@echo 'Done!'

.run_engine:
	./$(NAME) --gtest_filter='EngineDeathTest.*:EngineTest.*'
	@echo 'Done!'

########### TARGETS ##################################

all: .comp

test_dynamic: .check_compiled .comp .run

test_static: .check_compiled .set_static .comp .run

test_engine_dynamic: .check_compiled .set_engine .comp .run_engine

test_engine_static: .check_compiled .set_engine .set_static .comp .run_engine

installed_test_dynamic: .check_installed .set_installed .comp .run

installed_test_static: .check_installed .set_static .set_installed .comp .run

clean:
	rm -rf ./$(SRC_DIR)/*.o $(NAME)


