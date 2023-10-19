# ======== SDK Options ========
# INCLUDE_DIR =
LD_DIR = J:\packers\Themida\ThemidaV237\ThemidaSDK\Lib\COFF
LIB_NAME = user32.lib $(LD_DIR)\SecureEngineSDK32.lib

# ======== PACKER Options ========
# PACK_PROJECT =
PACKER = J:\packers\Themida\ThemidaV237\Themida.exe

# ======== PIN Options ========
ANALYSIS_PATH = J:\D-packer\analysis
PIN_DLL = J:\D-packer\pintool\MyPinTool.dll

# ======== OUTPUT DIR ========
DIR = K:\Config_test\Themida\Themida_V237\protect_application_FISH_WHITE

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
PACKED_EXIST = $(wildcard *_packed.exe)
EXE_TMP = $(filter-out $(PACKED_EXIST),$(EXE_EXIST))
PACK_TARGET = $(subst .exe,_packed.exe,$(EXE_TMP))

PRELOG_TARGET = $(subst .exe,.prelog,$(EXE_TMP))
TRACE_TARGET = $(subst .prelog,_packed.log,$(PRELOG_TARGET))
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
	rm -f *_packed.exe

.PHONY: logclean
logclean:
	rm -f *.log
	rm -f *.prelog

.PHONY: execlean
execlean:
	rm -f *.exe

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


%_packed.exe:%.exe
	$(PACKER) /q /protect $(DIR)\$(subst .exe,.tmd,$<) /inputfile $(DIR)\$< /outputfile $(DIR)\$@

%.exe:%.obj
	$(LINKER) $(L_DEFAULT_FLAGS) $(LFLAGS) $< $(LIB_NAME)
	$(info LINK $< -o $@)

%.obj:%.c
	$(CC) $(C_DEFAULT_FLAGS) $(CFLAGS) /c $< /Fo$@
	$(info CC $< -o $@)

%.prelog:%.exe
	python $(ANALYSIS_PATH)\\PreAnalysis.py -f $<

%_packed.log:%.prelog
	pin -t $(PIN_DLL) -i $< -- $(subst .log,.exe,$@)

%_packed.json:%_packed.log
	python $(ANALYSIS_PATH)\\BytesAnalysis.py -f $<
