DEPS_FILES := \
	X509-ML-DSA-2024.asn \
	./examples/ML-DSA-44.crt \
	./examples/ML-DSA-44.crt.txt \
	./examples/ML-DSA-44.priv \
	./examples/ML-DSA-44.priv.txt \
	./examples/ML-DSA-44.pub \
	./examples/ML-DSA-44.pub.txt \
	./examples/ML-DSA-65.crt \
	./examples/ML-DSA-65.crt.txt \
	./examples/ML-DSA-65.priv \
	./examples/ML-DSA-65.priv.txt \
	./examples/ML-DSA-65.pub \
	./examples/ML-DSA-65.pub.txt \
	./examples/ML-DSA-87.crt \
	./examples/ML-DSA-87.crt.txt \
	./examples/ML-DSA-87.priv \
	./examples/ML-DSA-87.priv.txt \
	./examples/ML-DSA-87.pub \
	./examples/ML-DSA-87.pub.txt \

LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update $(CLONE_ARGS) --init
else
	git clone -q --depth 10 $(CLONE_ARGS) \
	    -b main https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
