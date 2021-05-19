
TOOLS= \
	imix \
	itrace

TOOL_DIRS=$(addsuffix -pin, $(TOOLS))

default: $(TOOL_DIRS)

.PHONY: $(TOOL_DIRS)

$(TOOL_DIRS):
	$(MAKE) -C $@
