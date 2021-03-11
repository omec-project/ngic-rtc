# Copyright (c) 2020 Sprint
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

CC := g++
LD := g++
SRCDIR := ./src
EXEDIR := ./bin
EXE := d_admf

SOURCES := $(shell find $(SRCDIR) -type f -name '*.cpp')
OBJECTS := $(patsubst $(SRCDIR)/%,$(SRCDIR)/%,$(SOURCES:.cpp=.o))
CPPFLAGS := -std=c++14 -Wreturn-type -pthread $(LIBS) -Wall -Werror 

INC := -I/usr/local/include/epc/ -I ./include/ -I ../common/ 
LIBS :=	\
	/usr/local/lib/libepc.a			\
	/usr/local/lib/libpistache.a		\
	-L /usr/local/lib/ -lcares		\
	/usr/local/lib/libfdcore.so		\
	/usr/local/lib/libfdproto.so		\
	-L /usr/lib/				\
	-lrt					\
	-lcurl

$(EXE): $(OBJECTS)
	@echo " $(LD) $(INC) $(CPPFLAGS) -o $(EXEDIR)/$(EXE) $(OBJECTS) \
		 $(LIBS)"; \
		$(LD) $(INC) $(CPPFLAGS) -o $(EXEDIR)/$(EXE) $(OBJECTS) \
		 $(LIBS)

$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	@echo " $(CC) $(CPPFLAGS) $(INC) -c -o $@ $<"; $(CC) $(CPPFLAGS) $(INC) -c -o $@ $<

clean:
	rm -f $(SRCDIR)/*.o
	rm -f $(EXEDIR)/$(EXE)

