# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2017 Intel Corporation


ROOT=.

CC := gcc

TARGET_DIR := $(ROOT)/lib

SRCDIR := $(ROOT)/src
TARGET := libgtpv2c.so
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
