#
# Copyright (c) 2019 Sprint
# Copyright (c) 2020 T-Mobile
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

TARGET_DIR := $(ROOT)

SRCDIR := $(ROOT)/src
TARGET := gx_app
BUILDDIR := $(ROOT)/obj

SRCEXT := c

SOURCES := $(shell find $(SRCDIR) -type f -name '*.$(SRCEXT)')
SOURCES += ../ipc_api.c

OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))

#CFLAGS +=  -fPIC -Wall
CFLAGS +=  -fPIC -Wall -Werror

ifeq ($(DEBUG),1)
	CFLAGS += -g3
#un-comment below line to remove all Debug logs for testing.
	CFLAGS += -DGX_DEBUG
else
	CFLAGS += -O3
endif

CFLAGS += -I$(ROOT)/../
CFLAGS += -I$(ROOT)/include
CFLAGS += -I$(ROOT)/../../third_party/libgtpv2c/include
LIB_PATH :=/usr/local/lib
LIBS := -lfdproto -lfdcore

LFLAGS :=

$(TARGET_DIR)/$(TARGET): $(OBJECTS)
	@echo " Linking..."
	@mkdir -p $(BUILDDIR)
	@mkdir -p $(TARGET_DIR)

	$(CC) $(LFLAGS) $^ -o $(TARGET_DIR)/$(TARGET) -L$(LIB_PATH) $(LIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	@echo " $(CC) $(CFLAGS) -c -o $@ $<"; $(CC) $(CFLAGS) -c -o $@ $<

all:$(TARGET)

clean:
	@echo " Cleaning...";
	@echo " $(RM) -r $(BUILDDIR) $(TARGET_DIR)/gx_app"; $(RM) -r $(BUILDDIR) $(TARGET_DIR)/gx_app

.PHONY: clean
