CC = g++
CPPFLAGS = -std=c++98 -fPIC

#LIBS
LIBS = -lp11 -lcrypto -lssl
LIBS_STATIC= /usr/local/ssl/lib/libcrypto.a /usr/local/ssl/lib/libssl.a -lp11 
SSL_INCLUDES = -I/usr/local/ssl/include/
INCLUDES = -I./include $(SSL_INCLUDES)
NAME = libcryptosec.so

CPP_SRCS := $(shell find src -name "*.cpp")
OBJS += $(CPP_SRCS:.cpp=.o)
CPP_DEPS += $(CPP_SRCS:.cpp=.d)

ARQ= $(shell uname -m)
LIBDIR = /usr/lib
ifeq ($(ARQ), x86_64)
LIBDIR=/usr/lib64
endif

src/%.o: ./src/%.cpp
	@echo 'Building file: $<'
	$(CC) $(CPPFLAGS) $(INCLUDES) -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo ' '

$(NAME): $(OBJS)
	$(CC) $(CPPFLAGS) -shared -o $(NAME) $(OBJS) $(LIBS)
	@echo 'Build complete!'

static: $(OBJS)
	$(CC) $(CPPFLAGS) -shared -o $(NAME) $(OBJS) $(LIBS_STATIC)
	@echo 'Build complete!'

static_release: static
	strip $(NAME)

clean:
	rm -rf $(CPP_DEPS) $(OBJS) $(NAME)
	

install: $(NAME)
	@echo 'Installing libcryptosec ...'
	@mkdir -p $(LIBDIR)
	@cp libcryptosec.so $(LIBDIR)
	@mkdir -m 0755 -p /usr/include/libcryptosec
	@mkdir -m 0755 -p /usr/include/libcryptosec/exception
	@mkdir -m 0755 -p /usr/include/libcryptosec/certificate
	@mkdir -m 0755 -p /usr/include/libcryptosec/ec
	@cp -f include/libcryptosec/*.h /usr/include/libcryptosec/
	@cp -f include/libcryptosec/exception/* /usr/include/libcryptosec/exception
	@cp -f include/libcryptosec/certificate/* /usr/include/libcryptosec/certificate
	@cp -f include/libcryptosec/ec/* /usr/include/libcryptosec/ec
	@echo 'Instalation complete!'

uninstall:
	@echo 'Uninstalling libcryptosec ...'
	@rm -rf $(LIBDIR)/$(NAME)
	@rm -rf /usr/include/libcryptosec
	@echo 'Uninstalation complete!'
