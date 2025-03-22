CC:=gcc
CFLAGS:=-Iinclude/ -Werror -Wall -m64 -g
LDLIBS:=

TARGET:=reverse_proxy

SRCDIR:=src
OBJDIR:=obj

SRCS:=$(wildcard $(SRCDIR)/*.c) $(wildcard $(SRCDIR)/*/*.c)
OBJS:=$(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

rm:=rm -rf
mkdir:=mkdir -p

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	cppcheck --enable=performance unusedFunction --error-exitcode=1 --check-level=exhaustive $(SRCS)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(mkdir) $(@D)
	$(CC) $(CFLAGS) -c $^ $(LDLIBS) -o $@

clean:
	@$(rm) $(OBJDIR) $(TARGET)

