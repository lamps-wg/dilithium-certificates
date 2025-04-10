DEPS_FILES := \
	X509-ML-DSA-2025.asn \
	./examples/ML-DSA-44.crt \
	./examples/ML-DSA-44.crt.txt \
	./examples/ML-DSA-44-seed.priv \
	./examples/ML-DSA-44-expanded.priv \
	./examples/ML-DSA-44-both.priv \
	./examples/ML-DSA-44-seed.priv.txt \
	./examples/ML-DSA-44-expanded.priv.txt \
	./examples/ML-DSA-44-both.priv.txt \
	./examples/ML-DSA-44.pub \
	./examples/ML-DSA-44.pub.txt \
	./examples/ML-DSA-65.crt \
	./examples/ML-DSA-65.crt.txt \
	./examples/ML-DSA-65-seed.priv \
	./examples/ML-DSA-65-expanded.priv \
	./examples/ML-DSA-65-both.priv \
	./examples/ML-DSA-65-seed.priv.txt \
	./examples/ML-DSA-65-expanded.priv.txt \
	./examples/ML-DSA-65-both.priv.txt \
	./examples/ML-DSA-65.pub \
	./examples/ML-DSA-65.pub.txt \
	./examples/ML-DSA-87.crt \
	./examples/ML-DSA-87.crt.txt \
	./examples/ML-DSA-87-seed.priv \
	./examples/ML-DSA-87-expanded.priv \
	./examples/ML-DSA-87-both.priv \
	./examples/ML-DSA-87-seed.priv.txt \
	./examples/ML-DSA-87-expanded.priv.txt \
	./examples/ML-DSA-87-both.priv.txt \
	./examples/ML-DSA-87.pub \
	./examples/ML-DSA-87.pub.txt \
        ./examples/bad-ML-DSA-44-1.priv \
        ./examples/bad-ML-DSA-44-2.priv \
        ./examples/bad-ML-DSA-44-3.priv \

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
