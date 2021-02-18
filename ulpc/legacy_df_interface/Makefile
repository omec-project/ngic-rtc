CC := g++ # This is the main compiler
CP := cp -r
SRCDIR := src
BUILDDIR := build
TARGETDIR := lib
TARGET := $(TARGETDIR)/libLegacyInterface.so
DESTDIR := ../df/lib

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
DEPENDS := $(OBJECTS:%.o=%.d)
CFLAGS := -std=c++14 -Wall -Werror -fPIC
LFLAGS := -pthread -lpthread
LIBFLAGS := -shared -fPIC

EPCTOOLS := /usr/local/lib/libepc.a

LIBS := \
	-lrt	\
	-ldl

INCS := \
	-I ./include \
	-I /usr/local/include/epc

$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@mkdir -p $(TARGETDIR)
	@echo " $(CC) $(LIBFLAGS) $(LIBS) $^ $(EPCTOOLS) -o $(TARGET)";	\
		$(CC) $(LIBFLAGS) $(LIBS) $^ $(EPCTOOLS) -o $(TARGET)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INCS) -MMD -c -o $@ $<"; $(CC) $(CFLAGS) $(INCS) -MMD -c -o $@ $<

clean:
	@echo " Cleaning...";
	@echo " $(RM) -r $(BUILDDIR) $(TARGET)"; $(RM) -r $(BUILDDIR) $(TARGET)

-include $(DEPENDS)

install:
	@echo "Copying library file...";
	@echo "$(CP) $(TARGET) $(DESTDIR)";
	@echo "$?"

.PHONY: clean
