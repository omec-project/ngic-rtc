#
# Copyright (c) 2019 Sprint
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


ROOT=.

CC := gcc

TARGET_DIR := $(ROOT)/lib

SRCDIR := $(ROOT)/src
TARGET := libpfcp.so
BUILDDIR := $(ROOT)/obj

SRCEXT := c

SOURCES := $(shell find $(SRCDIR) -type f -name '*.$(SRCEXT)')

OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))

CFLAGS +=  -fPIC -Wall

ifeq ($(DEBUG),1)
	CFLAGS += -g3
else
	CFLAGS += -O3
endif

INCS := -I$(ROOT)/include
LIB_PATH :=
LIBS :=

LFLAGS := -shared

$(TARGET_DIR)/$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@mkdir -p $(BUILDDIR)
	@mkdir -p $(TARGET_DIR)

	$(CC) $(LFLAGS) $^ -o $(TARGET_DIR)/$(TARGET) $(LIB_PATH) $(LIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) $(INCS) -c -o $@ $<"; $(CC) $(CFLAGS) $(INCS) -c -o $@ $<

all:$(TARGET)

clean:
	@echo " Cleaning...";
	@echo " $(RM) -r $(BUILDDIR) $(TARGET_DIR)"; $(RM) -r $(BUILDDIR) $(TARGET_DIR)

.PHONY: clean
