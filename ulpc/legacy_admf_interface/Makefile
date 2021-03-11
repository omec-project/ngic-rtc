# Copyright (c) 202- Sprint
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CC := g++ # This is the main compiler
CP := cp -r
SRCDIR := src
BUILDDIR := build
TARGETDIR := lib
TARGET := $(TARGETDIR)/libLegacyAdmfInterface.so
DESTDIR := ../admf/lib

SRCEXT := cpp
SOURCES := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
DEPENDS := $(OBJECTS:%.o=%.d)
CFLAGS := -std=c++14 -Wall -Werror -fPIC
LFLAGS := -pthread -lpthread
LIBFLAGS := -shared -fPIC

EPCTOOLS := /usr/local/lib/libepc.a

LIBS := \
	-lrt    \
	-ldl    \
	-lcurl

INCS := \
	-I ./include \
	-I /usr/local/include/epc

$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@mkdir -p $(TARGETDIR)
	@echo " $(CC) $(LIBFLAGS) $(LIBS) $^ $(EPCTOOLS) -o $(TARGET)"; \
		$(CC) $(LIBFLAGS) -o $(TARGET) $^ $(LIBS) $(EPCTOOLS) 

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
