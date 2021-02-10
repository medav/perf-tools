define env-msg

The following environment variables must be defined:
    PERF_TOOLS (suggested: $(PWD)/..)
    PIN_ROOT (suggested: $(PWD)/../pin-3.17)

Additionally, $$PERF_TOOLS/bin must be in your $$PATH.

(Do this in your .bashrc)

endef

ifndef VIOLET_TOOLS
$(error $(env-msg))
endif

ifndef VIOLET_STACK
$(error $(env-msg))
endif

TOOLS= \
	icount \
	imix \
	itrace

TOOL_DIRS=$(addsuffix $(TOOLS),-pin)

.PHONY: $(TOOL_DIRS)

$(TOOL_DIRS):
	$(MAKE) -c $@
