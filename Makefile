CC:=gcc
CFLAGS:=-Wall -Iinclude/
STATIC:=-static

LDLIBS:=

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
DBGCFLAGS:=-O0 -Werror -std=c99 -g

# Utility commands
rm:=rm -rf
mkdir:=mkdir -p

.PHONY: all release debug clean

all: release

# Release rules
release: $(RELTARGET)

$(RELTARGET): $(RELOBJS)
	$(CC) $(CFLAGS) $(RELCFLAGS) $(STATIC) $^ $(LDLIBS) -o $@

$(RELDIR)/$(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(mkdir) $(@D)
	$(CC) $(CFLAGS) $(RELCFLAGS) -c $< $(LDLIBS) -o $@

# Debug rules
debug: $(DBGTARGET)

$(DBGTARGET): $(DBGOBJS)
	$(CC) $(CFLAGS) $(DBGCFLAGS) $(STATIC) $^ $(LDLIBS) -o $@

$(DBGDIR)/$(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(mkdir) $(@D)
	$(CC) $(CFLAGS) $(DBGCFLAGS) -c $< $(LDLIBS) -o $@

# Other rules
clean:
	@$(rm) $(DBGDIR) $(RELDIR)

