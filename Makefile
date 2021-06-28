define env-msg

The following environment variables must be defined:
    PERF_TOOLS (suggested: $(PWD))
    PIN_ROOT (suggested: $(PWD)/pin-3.17)

Additionally, $$PERF_TOOLS/bin must be in your $$PATH.

(Do this in your .bashrc)

endef

ifndef PERF_TOOLS
$(error $(env-msg))
endif

ifndef PIN_ROOT
$(error $(env-msg))
endif

.PHONY: default

default:
	$(MAKE) -C pintools
