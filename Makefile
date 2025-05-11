# Compiler configuration
CC:=gcc
CFLAGS:=-Iinclude/ -Werror -Wall -m64 -std=c99 -pedantic
LDLIBS:=

# Target file name
TARGET:=reverse_proxy

# Source and object files configuration
SRCDIR:=src
OBJDIR:=obj

SRCS:=$(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/*/*.c)
OBJS:=$(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Release configuration
RELDIR:=release
RELTARGET:=$(RELDIR)/$(TARGET)
RELOBJS:=$(addprefix $(RELDIR)/, $(OBJS))
RELCFLAGS:=-O3

# Debug configuration
DBGDIR:=debug
DBGTARGET:=$(DBGDIR)/$(TARGET)
DBGOBJS:=$(addprefix $(DBGDIR)/, $(OBJS))
DBGCFLAGS:=-g -O0

# Utility commands
rm:=rm -rf
mkdir:=mkdir -p

.PHONY: all check clean debug release

all: release

# Release rules
release: check $(RELTARGET)

$(RELTARGET): $(RELOBJS)
	$(CC) $(CFLAGS) $(RELCFLAGS) $^ $(LDLIBS) -o $@

$(RELDIR)/$(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(mkdir) $(@D)
	$(CC) $(CFLAGS) $(RELCFLAGS) -c $^ $(LDLIBS) -o $@

# Debug rules
debug: check $(DBGTARGET)

$(DBGTARGET): $(DBGOBJS)
	$(CC) $(CFLAGS) $(DBGCFLAGS) $^ $(LDLIBS) -o $@

$(DBGDIR)/$(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(mkdir) $(@D)
	$(CC) $(CFLAGS) $(DBGCFLAGS) -c $^ $(LDLIBS) -o $@

# Other rules
check:
	cppcheck --enable=performance unusedFunction --error-exitcode=1 --check-level=exhaustive $(SRCS)

clean:
	@$(rm) $(DBGDIR) $(RELDIR)

