# ======== SDK Options ========
# INCLUDE_DIR =
# LD_DIR =
LIB_NAME = user32.lib

# ======== PACKER Options ========
# PACK_PROJECT =
PACKER = J:\packers\PECompact\PECompact3.11.00.01\pec2gui.exe

# ======== PIN Options ========
ANALYSIS_PATH = J:\D-packer\analysis
PIN_DLL = J:\D-packer\pintool\MyPinTool.dll

# ======== OUTPUT DIR ========
DIR = K:\Config_test\PECompact\PECompact_V311\aplib1

# ======== Makefile rules ========
CC = cl
C_DEFAULT_FLAGS = /GS-
# CFLAGS =

LINKER = link
L_DEFAULT_FLAGS = /SAFESEH:NO /DYNAMICBASE:NO /NXCOMPAT:NO
# LFLAGS = 



SRC = $(wildcard *.c)
OBJ_TARGET = $(subst .c,.obj,$(SRC))
EXE_TARGET = $(subst .c,.exe,$(SRC))

EXE_EXIST = $(wildcard *.exe)
BACKUP_EXIST = $(wildcard *.exe.pec2bac)
PACKED_EXIST = $(subst .exe.pec2bac,.exe,$(BACKUP_EXIST))
EXE_TMP = $(filter-out $(PACKED_EXIST),$(EXE_EXIST))
PACK_TARGET = $(subst .exe,.exe.pec2bac,$(EXE_TMP))

PRELOG_TARGET = $(subst .exe,.prelog,$(PACKED_EXIST))
TRACE_TARGET = $(subst .prelog,.log,$(PRELOG_TARGET))
ANALYSIS_TARGET = $(subst .log,.json,$(TRACE_TARGET))



.PHONY: all
all: exe pack pin

.PHONY: build
build: exe pack

.PHONY: exe
exe: $(EXE_TARGET)

.PHONY: pack
pack: $(PACK_TARGET)

.PHONY: prelog
prelog: $(PRELOG_TARGET)

.PHONY: log
log: $(TRACE_TARGET)

.PHONY: analysis
analysis: $(ANALYSIS_TARGET)

.PHONY: pin
pin: prelog log analysis



.PHONY: clean
clean:
	echo "please use packclean / logclean / execlean / cclean"

.PHONY: packclean
vmpclean:
	rm -f *.exe

.PHONY: logclean
logclean:
	rm -f *.log
	rm -f *.prelog

.PHONY: execlean
execlean:
	rm -f *.exe
	rm -f *.exe.pec2bac

.PHONY: cclean
cclean:
	rm -f *.c

.PHONY: clear
clear: packclean logclean execlean cclean

.PHONY: debug
debug:
	@echo EXE_EXIST: $(EXE_EXIST)
	@echo PACKED_EXIST: $(PACKED_EXIST)
	@echo EXE_TMP: $(EXE_TMP)
	@echo PACK_TARGET: $(PACK_TARGET)
	@echo PRELOG_TARGET: $(PRELOG_TARGET)
	@echo TRACE_TARGET: $(TRACE_TARGET)

%.exe.pec2bac:%.exe
	$(PACKER) /project=$(DIR)\$(subst .exe,.pec2prj,$<) /AUTO

%.exe:%.obj
	$(LINKER) $(L_DEFAULT_FLAGS) $(LFLAGS) $< $(LIB_NAME)
	$(info LINK $< -o $@)

%.obj:%.c
	$(CC) $(C_DEFAULT_FLAGS) $(CFLAGS) /c $< /Fo$@
	$(info CC $< -o $@)

%.prelog:%.exe
	python $(ANALYSIS_PATH)\\PreAnalysis.py -f $(subst .exe,.exe.pec2bac,$<)

%.log:%.prelog
	pin -t $(PIN_DLL) -i $< -- $(subst .log,.exe,$@)

%.json:%.log
	python $(ANALYSIS_PATH)\\BytesAnalysis.py -f $<
